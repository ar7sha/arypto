use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "acrypto", version, about = "i will add this later..")]
#[command(group(
    clap::ArgGroup::new("mode")
        .required(true)
        .args(["encrypt", "decrypt"])
))]
pub struct Args {
    #[arg(short, long, value_name = "input file address")]
    pub input: String,

    #[arg(short, long, value_name = "encrypt mode")]
    pub encrypt: bool,

    #[arg(short, long, value_name = "decrypt mode")]
    pub decrypt: bool,

    #[arg(short, long, value_name = "output file address")]
    pub output: String,

    #[arg(
        long,
        short = 's',
        default_value_t = false,
        value_name = "this will decrypt file without checking sigs(slh-dsa and ml-dsa) , only for when you lost keys(they are stored in OS safe storage)"
    )]
    pub open_without_checking_signs: bool,
}

pub fn parse_args() -> (String, String, bool, bool, bool) {
    let args = Args::parse();
    (
        args.input,
        args.output,
        args.decrypt,
        args.encrypt,
        args.open_without_checking_signs,
    )
}
