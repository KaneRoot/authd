require "option_parser"

require "../src/authd.cr"

key_file       : String? = nil
login          : String? = nil
activation_key : String? = nil

OptionParser.parse do |parser|
	parser.unknown_args do |args|
		if args.size != 2
			puts "usage: #{PROGRAM_NAME} login activation_key [options]"
			exit 1
		end

		login, activation_key = args[0..1]
	end

	parser.on "-K file", "--key-file file", "Read the authd shared key from a file." do |file|
		key_file = file
	end

	parser.on "-h", "--help", "Prints this help message." do
		puts "usage: #{PROGRAM_NAME} <login> <email> <phone> [options]"
		puts parser
		exit 0
	end
end

begin
	authd = AuthD::Client.new
	authd.key = File.read(key_file.not_nil!).chomp

	pp! r = authd.validate_user login.not_nil!, activation_key.not_nil!
rescue e
	puts "Error: #{e}"
	exit 1
end
