require "uuid"
require "option_parser"
require "openssl"
require "colorize"

require "jwt"
require "ipc"
require "dodb"

require "baguette-crystal-base"
require "grok"

require "./authd.cr"

extend AuthD

class Baguette::Configuration
	class Auth < IPC
		property recreate_indexes       : Bool          = false
		property storage                : String        = "storage"
		property registrations          : Bool          = false
		property require_email          : Bool          = false
		property activation_url         : String?       = nil
		property field_subject          : String?       = nil
		property field_from             : String?       = nil
		property read_only_profile_keys : Array(String) = Array(String).new

		property print_password_recovery_parameters : Bool = false
	end
end

# Provides a JWT-based authentication scheme for service-specific users.
class AuthD::Service < IPC::Server
	property configuration   : Baguette::Configuration::Auth

	# DB and its indexes.
	property users           : DODB::DataBase(User)
	property users_per_uid   : DODB::Index(User)
	property users_per_login : DODB::Index(User)

	# #{@configuration.storage}/last_used_uid
	property last_uid_file   : String

	def initialize(@configuration)
		@users = DODB::DataBase(User).new @configuration.storage
		@users_per_uid   = @users.new_index "uid",   &.uid.to_s
		@users_per_login = @users.new_index "login", &.login

		@last_uid_file = "#{@configuration.storage}/last_used_uid"

		if @configuration.recreate_indexes
			@users.reindex_everything!
		end

		super "auth"
	end

	def hash_password(password : String) : String
		digest = OpenSSL::Digest.new "sha256"
		digest << password
		digest.hexdigest
	end

	def new_uid
		begin
			uid = File.read(@last_uid_file).to_i
		rescue
			uid = 999
		end

		uid += 1

		File.write @last_uid_file, uid.to_s

		uid
	end

	def handle_request(event : IPC::Event::MessageReceived)
		request_start = Time.utc

		request = AuthD.requests.parse_ipc_json event.message

		if request.nil?
			raise "unknown request type"
		end

		request_name = request.class.name.sub /^AuthD::Request::/, ""
		Baguette::Log.debug "<< #{request_name}"

		response = begin
			request.handle self, event
		rescue e : UserNotFound
			Baguette::Log.error "#{request_name} user not found"
			AuthD::Response::Error.new "authorization error"
		rescue e : AuthenticationInfoLacking
			Baguette::Log.error "#{request_name} lacking authentication info"
			AuthD::Response::Error.new "authorization error"
		rescue e : AdminAuthorizationException
			Baguette::Log.error "#{request_name} admin authentication failed"
			AuthD::Response::Error.new "authorization error"
		rescue e
			Baguette::Log.error "#{request_name} generic error #{e}"
			AuthD::Response::Error.new "unknown error"
		end

		# If clients sent requests with an “id” field, it is copied
		# in the responses. Allows identifying responses easily.
		response.id = request.id

		send event.fd, response

		duration = Time.utc - request_start

		response_name = response.class.name.sub /^AuthD::Response::/, ""

		if response.is_a? AuthD::Response::Error
			Baguette::Log.warning ">> #{response_name} (#{response.reason})"
		else
			Baguette::Log.debug ">> #{response_name} (Total duration: #{duration})"
		end
	end

	def get_user_from_token(token : String)
		token_payload = Token.from_s(@configuration.shared_key, token)

		@users_per_uid.get? token_payload.uid.to_s
	end

	def run
		Baguette::Log.title "Starting authd"

		@base_timer = @configuration.ipc_timer
		@timer      = @configuration.ipc_timer

		self.loop do |event|
			case event
			when IPC::Event::Timer
				Baguette::Log.debug "Timer" if @configuration.print_ipc_timer

			when IPC::Event::MessageReceived
				Baguette::Log.debug "Received message from #{event.fd}" if @configuration.print_ipc_message_received
				begin
					handle_request event
				rescue e
					Baguette::Log.error "#{e.message}"
					# send event.fd, Response::Error.new e.message
				end

			when IPC::Event::MessageSent
				Baguette::Log.debug "Message sent to #{event.fd}" if @configuration.print_ipc_message_sent

			when IPC::Exception
				Baguette::Log.error "IPC::Exception"
				pp! event
			else
				Baguette::Log.error "Not implemented behavior for event: #{event}"
			end
		end

	end
end


begin
	simulation, no_configuration, configuration_file = Baguette::Configuration.option_parser

	configuration = if no_configuration
		Baguette::Log.info "do not load a configuration file."
		Baguette::Configuration::Auth.new
	else
		Baguette::Configuration::Auth.get(configuration_file) ||
			Baguette::Configuration::Auth.new
	end

	Baguette::Context.verbosity = configuration.verbosity

	if key_file = configuration.shared_key_file
		configuration.shared_key = File.read(key_file).chomp
	end

	OptionParser.parse do |parser|
		parser.banner = "usage: authd [options]"

		parser.on "--storage directory", "Directory in which to store users." do |directory|
			configuration.storage = directory
		end

		parser.on "-K file", "--key-file file", "JWT key file" do |file_name|
			configuration.shared_key = File.read(file_name).chomp
		end

		parser.on "-R", "--allow-registrations" do
			configuration.registrations = true
		end

		parser.on "-E", "--require-email" do
			configuration.require_email = true
		end

		parser.on "-t subject", "--subject title", "Subject of the email." do |s|
			configuration.field_subject = s
		end

		parser.on "-f from-email", "--from email", "'From:' field to use in activation email." do |f|
			configuration.field_from = f
		end

		parser.on "-u", "--activation-url url", "Activation URL." do |opt|
			configuration.activation_url = opt
		end

		parser.on "-x key", "--read-only-profile-key key", "Marks a user profile key as being read-only." do |key|
			configuration.read_only_profile_keys.push key
		end

		parser.on "-h", "--help", "Show this help" do
			puts parser
			exit 0
		end
	end

	if simulation
		pp! configuration
		exit 0
	end

	AuthD::Service.new(configuration).run

rescue e : OptionParser::Exception
	Baguette::Log.error e.message
rescue e
	Baguette::Log.error "exception raised: #{e.message}"
	e.backtrace.try &.each do |line|
		STDERR << "  - " << line << '\n'
	end
end

