require "option_parser"

require "../src/authd.cr"

# key_file       : String? = nil
login          : String? = nil
activation_key : String? = nil

OptionParser.parse do |parser|
	parser.unknown_args do |args|
		if args.size != 1
			puts "usage: #{PROGRAM_NAME} login-to-search [options]"
			exit 1
		end

		login = args[0]
	end

	#parser.on "-K file", "--key-file file", "Read the authd shared key from a file." do |file|
	#	key_file = file
	#end

	parser.on "-h", "--help", "Prints this help message." do
		puts "usage: #{PROGRAM_NAME} login-to-search [options]"
		puts parser
		exit 0
	end
end

begin
	authd = AuthD::Client.new
	# authd.key = File.read(key_file.not_nil!).chomp

	pp! r = authd.search_user login.not_nil!
rescue e
	puts "Error: #{e}"
	exit 1
end
