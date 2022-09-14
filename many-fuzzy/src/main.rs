use crate::stats::Statistics;
use clap::Parser;
use coset::{CoseSign1, TaggedCborSerializable};
use fuzz::FuzzGenerator;
use many_identity::{verifiers::AnonymousVerifier, AnonymousIdentity, Identity};
use many_identity_dsa::{CoseKeyIdentity, CoseKeyVerifier};
use many_protocol::{decode_response_from_cose_sign1, RequestMessage, RequestMessageBuilder};
use rand::{Rng, SeedableRng};
use std::num::ParseIntError;
use std::sync::Arc;
use tokio::sync::oneshot::Sender;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio::time::{interval, Duration};
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;
use tracing::level_filters::LevelFilter;
use tracing::{error, trace};

mod fuzz;
mod parsers;
mod stats;

fn validate_nb_threads(v: &str) -> Result<(), String> {
    let threads: usize = v.parse().map_err(|e: ParseIntError| e.to_string())?;
    if threads == 0 {
        return Err("Number of threads must be greater than 0.".to_string());
    }

    Ok(())
}

#[derive(Parser)]
struct Opts {
    /// Increase output logging verbosity to DEBUG level.
    #[clap(short, long, parse(from_occurrences))]
    verbose: i8,

    /// Suppress all output logging. Can be used multiple times to suppress more.
    #[clap(short, long, parse(from_occurrences))]
    quiet: i8,

    /// Number of threads to use. By default, 10.
    #[clap(short, long, default_value = "10", validator = validate_nb_threads)]
    threads: usize,

    /// Whether to include a nonce in the message. Default to false.
    #[clap(long)]
    nonce: bool,

    #[clap(subcommand)]
    subcommand: SubCommand,
}

#[derive(Parser)]
enum SubCommand {
    /// Run the fuzzer against a server.
    Fuzz(FuzzOpt),
}

#[derive(Parser, Debug)]
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
    pem: Option<Vec<String>>,

    /// The server to connect to.
    server: url::Url,

    /// The endpoint to call.
    endpoint: String,

    /// The content of the message itself (its payload).
    /// Will replace any substring `%()` with fuzzed values.
    data: String,

    /// Whether to wait for async tokens to include resolution statistics.
    #[clap(long)]
    r#async: bool,
}

fn split_pem_args(
    pem_list: Vec<String>,
) -> Result<impl Iterator<Item = Arc<dyn Identity>>, String> {
    Ok(pem_list
        .iter()
        .flat_map(|str| str.split(','))
        .map(|str| {
            let ident: Arc<dyn Identity> = if str == "anonymous" {
                Arc::new(AnonymousIdentity)
            } else {
                Arc::new(
                    CoseKeyIdentity::from_pem(
                        &std::fs::read_to_string(&str).map_err(|e| e.to_string())?,
                    )
                    .map_err(|e| e.to_string())?,
                )
            };
            Ok::<Arc<dyn Identity>, String>(ident)
        })
        .collect::<Result<Vec<Arc<dyn Identity>>, _>>()?
        .into_iter()
        .cycle())
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
            generator.fuzz(rng)
        });
        builder.data(cbor_diag::parse_diag(&data).unwrap().to_bytes());
        messages.push(builder.build().map_err(|e| e.to_string())?);
    }

    Ok(messages)
}

/// Start a thread that waits every seconds there is progress, or every 5 seconds if no
/// progress is made, and show the current progress (number of requests sent and number
/// of responses returned).
/// TODO: maybe this could be a progress bar.
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
    req: reqwest::RequestBuilder,
    msg: RequestMessage,
    signer: Arc<dyn Identity>,
    statistics: Statistics,
) -> JoinHandle<()> {
    let sign1 = coset::CoseSign1Builder::default()
        .payload(msg.to_bytes().unwrap())
        .build();
    let cose_sign1 = signer.sign_1(sign1).unwrap();
    tokio::spawn(async move {
        let body = cose_sign1.to_tagged_vec().unwrap();
        let post = req.body(body);
        statistics.request_counter.inc();

        // Do not include the signature generation and analyzing the response
        // in the measurement.
        let strategy = ExponentialBackoff::from_millis(10).map(jitter).take(5);
        let response = Retry::spawn(strategy, || async {
            let post = post.try_clone().unwrap();

            let start = Instant::now();
            let response = post.send().await;
            let elapsed = start.elapsed();
            response.map(|r| (r, elapsed))
        })
        .await;

        match response {
            Err(x) => {
                error!("transport error: {}", x.to_string().as_str());
                statistics.http_errors_counter.inc()
            }
            Ok((resp, elapsed)) => {
                statistics
                    .histogram()
                    .await
                    .record(elapsed.as_nanos() as u64)
                    .unwrap();

                let body = resp
                    .bytes()
                    .await
                    .map_err(|e| e.to_string())
                    .and_then(|bytes| {
                        trace!("received: {}", hex::encode(bytes.as_ref()));
                        decode_response_from_cose_sign1(
                            &CoseSign1::from_tagged_slice(bytes.as_ref())
                                .map_err(|e| e.to_string())?,
                            None,
                            &(AnonymousVerifier, CoseKeyVerifier),
                        )
                        .map_err(|e| e.to_string())
                    });

                match body {
                    Ok(msg) => match msg.data {
                        Ok(_) => statistics.many_success_counter.inc(),
                        Err(_) => statistics.many_errors_counter.inc(),
                    },
                    Err(e) => {
                        error!("err: {}", e);

                        statistics.http_errors_counter.inc()
                    }
                };
            }
        }
        statistics.response_counter.inc();
    })
}

fn main() {
    let Opts {
        verbose,
        quiet,
        threads,
        subcommand,
        nonce,
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

    let result = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async { execute(subcommand, nonce).await });

    match result {
        Ok(_) => {}
        Err(message) => {
            eprintln!("{}", message);
            std::process::exit(1);
        }
    }
}

async fn execute(subcommand: SubCommand, should_nonce: bool) -> Result<(), String> {
    match subcommand {
        SubCommand::Fuzz(o) => {
            tracing::debug!("{:?}", o);

            // Get all PEM files.
            let id_list =
                split_pem_args(o.pem.unwrap_or_else(|| vec!["anonymous".to_string()])).unwrap();

            let mut builder = RequestMessageBuilder::default();
            builder.method(o.endpoint);

            // We select a seed to be able to output it to the user and allow for replays.
            let seed = o.seed.unwrap_or_else(|| rand::thread_rng().gen::<u64>());
            tracing::info!(seed);

            let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
            let messages = create_messages(&mut rng, o.number, builder, &o.data).unwrap();

            let msg_it = messages.into_iter().zip(id_list);

            let mut handles = Vec::with_capacity(1024);

            let statistics = Statistics::default();
            let (stop_progress_tx, progress_thread_handle) =
                start_counting_thread(statistics.clone());
            let mut nonce: u64 = 0;

            let client = reqwest::ClientBuilder::new().build().unwrap();
            let r = client.post(o.server.clone());

            for (mut msg, signer) in msg_it {
                msg.from = if signer.address().is_anonymous() {
                    None
                } else {
                    Some(signer.address())
                };

                if should_nonce {
                    msg.nonce = Some(nonce.to_be_bytes().to_vec());
                    nonce += 1;
                }

                let statistics = statistics.clone();
                let handle = send_and_record(r.try_clone().unwrap(), msg, signer, statistics).await;
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
    Ok(())
}
