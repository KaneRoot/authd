require "option_parser"

require "../src/authd.cr"

key_file     : String? = nil
cli_login    : String? = nil
cli_service  : String? = nil
cli_resource : String? = nil
cli_permlvl  : String? = nil

OptionParser.parse do |parser|
	parser.unknown_args do |args|
		if 3 < args.size > 4
			puts "usage: #{PROGRAM_NAME} <uid> <service> <resource> <permlevel> [options]"
			puts parser
			exit 1
		end

		cli_login    = args[0]
		cli_service  = args[1]
		cli_resource = args[2] if args.size > 2
		cli_permlvl  = args[3] if args.size > 3
	end

	parser.on "-K file", "--key-file file", "Read the authd shared key from a file." do |file|
		key_file = file
	end

	parser.on "-h", "--help", "Prints this help message." do
		puts "usage:   #{PROGRAM_NAME} <uid> <service>      <resource> [permission] [options]"
		puts "example: #{PROGRAM_NAME} 1002  my-application chat       read"
		puts
		puts "permission list: none read edit admin"
		puts parser
		exit 0
	end
end

if cli_login.nil?
	STDERR.puts "no login provided"
	exit 1
end

login    = cli_login.not_nil!.to_i # not_nil!? O RLY?
service  = cli_service.not_nil!    # not_nil!
resource = cli_resource.not_nil!   # not_nil!

authd = AuthD::Client.new

begin
	key_file.try do |file| # FIXME: fail if missing?
		authd.key = File.read(file).chomp
	end

	if cli_permlvl.nil?
		pp! authd.check_permission login, service, resource
	else
		permlvl = cli_permlvl.not_nil!
		perm = AuthD::User::PermissionLevel.parse(permlvl)
		pp! authd.set_permission login, service, resource, perm
	end
rescue e : AuthD::Exception
	puts "error: #{e.message}"
end

authd.close

