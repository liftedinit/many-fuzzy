use crate::stats::Statistics;
use clap::Parser;
use fuzz::FuzzGenerator;
use many::message::{
    decode_response_from_cose_sign1, encode_cose_sign1_from_request, RequestMessage,
    RequestMessageBuilder,
};
use many::types::identity::CoseKeyIdentity;
use many::Identity;
use minicose::CoseSign1;
use rand::{Rng, SeedableRng};
use tokio::sync::oneshot::Sender;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio::time::{interval, Duration};
use tracing::level_filters::LevelFilter;

mod fuzz;
mod parsers;
mod stats;

#[derive(Parser)]
struct Opts {
    /// Increase output logging verbosity to DEBUG level.
    #[clap(short, long, parse(from_occurrences))]
    verbose: i8,

    /// Suppress all output logging. Can be used multiple times to suppress more.
    #[clap(short, long, parse(from_occurrences))]
    quiet: i8,

    #[clap(subcommand)]
    subcommand: SubCommand,
}

#[derive(Parser)]
enum SubCommand {
    /// Run the fuzzer against a server.
    Fuzz(FuzzOpt),
}

#[derive(Parser)]
struct FuzzOpt {
    /// Number of messages to create and send.
    #[clap(short)]
    number: u64,

    /// A seed to use for the Rng. By default does not seed the Rng and instead
    /// randomize it on start.
    #[clap(long)]
    seed: Option<u64>,

    /// One or more pem file(s) to sign messages, separated by a comma.
    /// If this is omitted, the message will be anonymous.
    /// The special string "anonymous" will be used to add anonymous
    /// to the list of pem files.
    #[clap(long)]
    pem: Option<String>,

    /// The identity to send it to.
    #[clap(long)]
    to: Option<Identity>,

    /// The server to connect to.
    server: url::Url,

    /// The endpoint to call.
    endpoint: String,

    /// The content of the message itself (its payload).
    /// Will replace any substring `%()` with fuzzed values.
    data: String,
}

fn split_pem_args(pem_list: String) -> Result<Vec<CoseKeyIdentity>, String> {
    pem_list
        .split(",")
        .map(|str| {
            if str == "anonymous" {
                Ok(CoseKeyIdentity::anonymous())
            } else {
                CoseKeyIdentity::from_pem(
                    &std::fs::read_to_string(&str).map_err(|e| e.to_string())?,
                )
            }
        })
        .collect()
}

fn create_messages(
    rng: &mut impl rand::Rng,
    count: u64,
    builder: RequestMessageBuilder,
    message: &str,
) -> Result<Vec<RequestMessage>, String> {
    let re = regex::Regex::new(r"%%|%\(([^\)]*)\)").unwrap();
    let mut messages = Vec::new();

    for _ in 0..count {
        let mut builder = builder.clone();
        let data = re.replace(message, |cap: &regex::Captures| {
            let ty = cap.get(1).unwrap();
            let mut generator = parsers::fuzz_string::generator(ty.as_str())
                .expect("Could not parse fuzzy parameters");
            let value = generator.fuzz(rng);

            value
        });
        builder.data(cbor_diag::parse_diag(&data).unwrap().to_bytes());
        messages.push(builder.build().map_err(|e| e.to_string())?);
    }

    Ok(messages)
}

/// Start a thread that waits every 2 seconds and show the current progress.
fn start_counting_thread(statistics: Statistics) -> (Sender<()>, JoinHandle<()>) {
    let (stop_thread_tx, mut stop_thread_rx) = tokio::sync::oneshot::channel();
    let thread_handle = tokio::spawn(async move {
        let mut interval = interval(Duration::from_millis(1000));
        // Only show every 5 seconds if nothing changed.
        let mut last_response = 0;
        let mut last_request = 0;
        let mut last_counter = 1;

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let (request, response) = (
                        statistics.request_counter.load(),
                        statistics.response_counter.load()
                    );

                    if last_response == response && last_request == request {
                        last_counter -= 1;
                        if last_counter == 0 {
                            tracing::info!(
                                "Requests: {:5} sent, {:5} received",
                                request, response
                            );
                            last_counter = 5;
                        }
                    } else {
                        last_response = response;
                        last_request = request;
                        last_counter = 5;
                        tracing::info!(
                            "Requests: {:5} sent, {:5} received",
                            request, response
                        );
                    }
                },
                _ = &mut stop_thread_rx => {
                    tracing::info!(
                        "Requests: {:5} sent, {:5} received",
                        statistics.request_counter.load(),
                        statistics.response_counter.load()
                    );
                    break;
                }
            }
        }
    });

    (stop_thread_tx, thread_handle)
}

/// Print out the statistics results to the user.
async fn show_statistics(statistics: Statistics) {
    let h = statistics.histogram().await;

    // Show the histogram results.
    println!("\n{}\n== Report {}\n", "=".repeat(80), "=".repeat(70));
    println!("Response time:\n");
    println!(
        "  Transport Errors: {}",
        statistics.http_errors_counter.load()
    );
    println!(
        "  Results (ok/err/queries): {}/{}/{}",
        statistics.many_success_counter.load(),
        statistics.many_errors_counter.load(),
        statistics.response_counter.load(),
    );

    // Find a good unit to show (either µs or ms).
    let (unit, dividend) = if h.max() > 10_000_000 {
        ("ms", 1_000_000)
    } else if h.max() > 10_000 {
        ("µs", 1_000)
    } else {
        ("ns", 1)
    };

    println!(
        "  Mean:{:8.0}{unit}\n  p50: {:8}{unit}\n  p90: {:8}{unit}\n  p99: {:8}{unit}\n  p999:{:8}{unit}\n  Max: {:8}{unit}",
        h.mean() / (dividend as f64),
        h.value_at_quantile(0.5) / dividend,
        h.value_at_quantile(0.9) / dividend,
        h.value_at_quantile(0.99) / dividend,
        h.value_at_quantile(0.999) / dividend,
        h.max() / dividend,
        unit = unit,
    );

    println!("\n{}", "=".repeat(80));
    let step = (h.max() - h.min()) / 20;

    for v in h.iter_linear(step).skip_while(|v| v.quantile() < 0.02) {
        if v.count_since_last_iteration() == 0 {
            continue;
        }

        println!(
            "{:8}µs | {:40} | {:5.1}th %-ile ({:4})",
            (v.value_iterated_to() + 1) / 1_000,
            "*".repeat(
                (v.count_since_last_iteration() as f64 * 40.0 / h.len() as f64).ceil() as usize
            ),
            v.percentile(),
            v.count_since_last_iteration(),
        );
    }
    println!("{}\n", "=".repeat(80));
}

// Send the request and record the result.
async fn send_and_record(
    url: url::Url,
    msg: RequestMessage,
    signer: CoseKeyIdentity,
    statistics: Statistics,
) -> JoinHandle<()> {
    let client = reqwest::ClientBuilder::new().build().unwrap();

    tokio::spawn(async move {
        let cose_sign1 = encode_cose_sign1_from_request(msg, &signer).unwrap();
        let body = cose_sign1.to_bytes().unwrap();
        let post = client.post(url).body(body);
        statistics.request_counter.inc();

        // Do not include the signature generation and analyzing the response
        // in the measurement.
        let start = Instant::now();
        let response = post.send().await;
        let elapsed = start.elapsed();

        statistics
            .histogram()
            .await
            .record(elapsed.as_nanos() as u64)
            .unwrap();

        match response {
            Err(_) => statistics.http_errors_counter.inc(),
            Ok(resp) => {
                let body = resp.bytes().await.map_err(|_| ()).and_then(|bytes| {
                    decode_response_from_cose_sign1(
                        CoseSign1::from_bytes(bytes.as_ref()).map_err(|_| ())?,
                        None,
                    )
                    .map_err(|_| ())
                });

                match body {
                    Ok(msg) => match msg.data {
                        Ok(_) => statistics.many_success_counter.inc(),
                        Err(_) => statistics.many_errors_counter.inc(),
                    },
                    Err(_) => statistics.http_errors_counter.inc(),
                };
            }
        }
        statistics.response_counter.inc();
    })
}

#[tokio::main(flavor = "multi_thread", worker_threads = 10)]
async fn main() {
    let Opts {
        verbose,
        quiet,
        subcommand,
    } = Opts::parse();
    let verbose_level = 2 + verbose - quiet;
    let log_level = match verbose_level {
        x if x > 3 => LevelFilter::TRACE,
        3 => LevelFilter::DEBUG,
        2 => LevelFilter::INFO,
        1 => LevelFilter::WARN,
        0 => LevelFilter::ERROR,
        x if x < 0 => LevelFilter::OFF,
        _ => unreachable!(),
    };
    tracing_subscriber::fmt().with_max_level(log_level).init();

    match subcommand {
        SubCommand::Fuzz(o) => {
            // Get all PEM files.
            let id_list = split_pem_args(o.pem.unwrap_or_else(|| "anonymous".to_string())).unwrap();

            let mut builder = RequestMessageBuilder::default();
            builder.method(o.endpoint);

            // We select a seed to be able to output it to the user and allow for replays.
            let seed = o.seed.unwrap_or_else(|| rand::thread_rng().gen::<u64>());
            tracing::info!(seed);

            let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
            let messages = create_messages(&mut rng, o.number, builder, &o.data).unwrap();

            let msg_it = messages.into_iter().zip(id_list.iter().cloned().cycle());

            let mut handles = Vec::with_capacity(1024);

            let statistics = Statistics::default();
            let (stop_progress_tx, progress_thread_handle) =
                start_counting_thread(statistics.clone());

            for (mut msg, signer) in msg_it {
                msg.from = if signer.identity.is_anonymous() {
                    None
                } else {
                    Some(signer.identity.clone())
                };

                let statistics = statistics.clone();
                let handle = send_and_record(o.server.clone(), msg, signer, statistics).await;
                handles.push(handle);
            }

            for h in handles {
                h.await
                    .expect("Unexpected errors waiting for all requests to be done");
            }

            // Terminate the thread that was showing the progress.
            stop_progress_tx
                .send(())
                .expect("Could not stop the counting thread properly.");
            progress_thread_handle
                .await
                .expect("Could not stop the counting thread properly.");

            show_statistics(statistics).await;
        }
    }
}
