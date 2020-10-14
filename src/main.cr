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

class AuthD::Service
	property registrations_allowed = false
	property require_email         = false
	property mailer_activation_url : String? = nil
	property mailer_field_from     : String? = nil
	property mailer_field_subject  : String? = nil
	property read_only_profile_keys = Array(String).new

	@users_per_login : DODB::Index(User)
	@users_per_uid   : DODB::Index(User)

	def initialize(@storage_root : String, @jwt_key : String)
		@users = DODB::DataBase(User).new @storage_root
		@users_per_uid   = @users.new_index "uid",   &.uid.to_s
		@users_per_login = @users.new_index "login", &.login

		@last_uid_file = "#{@storage_root}/last_used_uid"
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

	def handle_request(request : AuthD::Request?)
		case request
		when Request::GetToken
			begin
				user = @users_per_login.get request.login
			rescue e : DODB::MissingEntry
				return Response::Error.new "invalid credentials"
			end

			if user.nil?
				return Response::Error.new "invalid credentials"
			end

			if user.password_hash != hash_password request.password
				return Response::Error.new "invalid credentials"
			end

			user.date_last_connection = Time.local
			token = user.to_token

			# change the date of the last connection
			@users_per_uid.update user.uid.to_s, user

			Response::Token.new (token.to_s @jwt_key), user.uid
		when Request::AddUser
			# No verification of the users' informations when an admin adds it.
			# No mail address verification.
			if request.shared_key != @jwt_key
				return Response::Error.new "invalid authentication key"
			end

			if @users_per_login.get? request.login
				return Response::Error.new "login already used"
			end

			if @require_email && request.email.nil?
				return Response::Error.new "email required"
			end

			password_hash = hash_password request.password

			uid = new_uid

			user = User.new uid, request.login, password_hash
			user.contact.email = request.email unless request.email.nil?
			user.contact.phone = request.phone unless request.phone.nil?

			request.profile.try do |profile|
				user.profile = profile
			end

			# We consider adding the user as a registration
			user.date_registration = Time.local

			@users << user

			Response::UserAdded.new user.to_public
		when Request::ValidateUser
			user = @users_per_login.get? request.login

			if user.nil?
				return Response::Error.new "user not found"
			end

			if user.contact.activation_key.nil?
				return Response::Error.new "user already validated"
			end

			# remove the user contact activation key: the email is validated
			if user.contact.activation_key == request.activation_key
				user.contact.activation_key = nil
			else
				return Response::Error.new "wrong activation key"
			end

			@users_per_uid.update user.uid.to_s, user

			Response::UserValidated.new user.to_public
		when Request::GetUserByCredentials
			user = @users_per_login.get? request.login

			unless user
				return Response::Error.new "invalid credentials"
			end
			
			if hash_password(request.password) != user.password_hash
				return Response::Error.new "invalid credentials"
			end

			user.date_last_connection = Time.local

			# change the date of the last connection
			@users_per_uid.update user.uid.to_s, user

			Response::User.new user.to_public
		when Request::GetUser
			uid_or_login = request.user
			user = if uid_or_login.is_a? Int32
				@users_per_uid.get? uid_or_login.to_s
			else
				@users_per_login.get? uid_or_login
			end

			if user.nil?
				return Response::Error.new "user not found"
			end

			Response::User.new user.to_public
		when Request::ModUser
			if request.shared_key != @jwt_key
				return Response::Error.new "invalid authentication key"
			end

			uid_or_login = request.user
			user = if uid_or_login.is_a? Int32
				@users_per_uid.get? uid_or_login.to_s
			else
				@users_per_login.get? uid_or_login
			end

			unless user
				return Response::Error.new "user not found"
			end

			request.password.try do |s|
				user.password_hash = hash_password s
			end

			request.email.try do |email|
				user.contact.email = email
			end

			request.phone.try do |phone|
				user.contact.phone = phone
			end

			@users_per_uid.update user.uid.to_s, user

			Response::UserEdited.new user.uid
		when Request::Register
			if ! @registrations_allowed
				return Response::Error.new "registrations not allowed"
			end

			if @users_per_login.get? request.login
				return Response::Error.new "login already used"
			end

			if @require_email && request.email.nil?
				return Response::Error.new "email required"
			end

			mailer_activation_url = @mailer_activation_url
			if mailer_activation_url.nil?
				# In this case we should not accept its registration.
				return Response::Error.new "No activation URL were entered. Cannot send activation mails."
			end

			if ! request.email.nil?
				# Test on the email address format.
				grok = Grok.new [ "%{EMAILADDRESS:email}" ]
				result = grok.parse request.email.not_nil!
				email = result["email"]?

				if email.nil?
					return Response::Error.new "invalid email format"
				end
			end

			uid = new_uid
			password = hash_password request.password

			user = User.new uid, request.login, password
			user.contact.email = request.email unless request.email.nil?
			user.contact.phone = request.phone unless request.phone.nil?

			request.profile.try do |profile|
				user.profile = profile
			end

			user.date_registration = Time.local

			begin
				mailer_field_subject  = @mailer_field_subject.not_nil!
				mailer_field_from     = @mailer_field_from.not_nil!
				mailer_activation_url = @mailer_activation_url.not_nil!

				u_login          = user.login
				u_email          = user.contact.email.not_nil!
				u_activation_key = user.contact.activation_key.not_nil!

				# Once the user is created and stored, we try to contact him
				unless Process.run("activation-mailer", [
					"-l", u_login,
					"-e", u_email,
					"-t", mailer_field_subject,
					"-f", mailer_field_from,
					"-u", mailer_activation_url,
					"-a", u_activation_key
					]).success?
					raise "cannot contact user #{user.login} address #{user.contact.email}"
				end
			rescue e
				Baguette::Log.error "activation-mailer: #{e}"
				return Response::Error.new "cannot contact the user (not registered)"
			end

			# add the user only if we were able to send the confirmation mail
			@users << user

			Response::UserAdded.new user.to_public
		when Request::UpdatePassword
			user = @users_per_login.get? request.login

			unless user
				return Response::Error.new "invalid credentials"
			end

			if hash_password(request.old_password) != user.password_hash
				return Response::Error.new "invalid credentials"
			end

			user.password_hash = hash_password request.new_password

			@users_per_uid.update user.uid.to_s, user

			Response::UserEdited.new user.uid
		when Request::ListUsers
			# FIXME: Lines too long, repeatedly (>80c with 4c tabs).
			request.token.try do |token|
				user = get_user_from_token token

				return Response::Error.new "unauthorized (user not found from token)"

				return Response::Error.new "unauthorized (user not in authd group)" unless user.permissions["authd"]?.try(&.["*"].>=(User::PermissionLevel::Read))
			end

			request.key.try do |key|
				return Response::Error.new "unauthorized (wrong shared key)" unless key == @jwt_key
			end

			return Response::Error.new "unauthorized (no key nor token)" unless request.key || request.token

			Response::UsersList.new @users.to_h.map &.[1].to_public
		when Request::CheckPermission
			authorized = false

			if key = request.shared_key
				if key == @jwt_key
					authorized = true
				else
					return Response::Error.new "invalid key provided"
				end
			end

			if token = request.token
				user = get_user_from_token token

				if user.nil?
					return Response::Error.new "token does not match user"
				end

				if user.login != request.user && user.uid != request.user
					return Response::Error.new "token does not match user"
				end

				authorized = true
			end

			unless authorized
				return Response::Error.new "unauthorized"
			end

			user = case u = request.user
			when .is_a? Int32
				@users_per_uid.get? u.to_s
			else
				@users_per_login.get? u
			end

			if user.nil?
				return Response::Error.new "no such user"
			end

			service = request.service
			service_permissions = user.permissions[service]?

			if service_permissions.nil?
				return Response::PermissionCheck.new service, request.resource, user.uid, User::PermissionLevel::None
			end

			resource_permissions = service_permissions[request.resource]?

			if resource_permissions.nil?
				return Response::PermissionCheck.new service, request.resource, user.uid, User::PermissionLevel::None
			end

			return Response::PermissionCheck.new service, request.resource, user.uid, resource_permissions
		when Request::SetPermission
			unless request.shared_key == @jwt_key
				return Response::Error.new "unauthorized"
			end

			user = @users_per_uid.get? request.user.to_s

			if user.nil?
				return Response::Error.new "no such user"
			end

			service = request.service
			service_permissions = user.permissions[service]?

			if service_permissions.nil?
				service_permissions = Hash(String, User::PermissionLevel).new
				user.permissions[service] = service_permissions
			end

			if request.permission.none?
				service_permissions.delete request.resource
			else
				service_permissions[request.resource] = request.permission
			end

			@users_per_uid.update user.uid.to_s, user

			Response::PermissionSet.new user.uid, service, request.resource, request.permission
		when Request::AskPasswordRecovery

			uid_or_login = request.user
			user = if uid_or_login.is_a? Int32
				@users_per_uid.get? uid_or_login.to_s
			else
				@users_per_login.get? uid_or_login
			end

			if user.nil?
				return Response::Error.new "no such user"
			end

			if user.contact.email != request.email
				# Same error as when users are not found.
				return Response::Error.new "no such user"
			end

			user.password_renew_key = UUID.random.to_s

			@users_per_uid.update user.uid.to_s, user

			unless (mailer_activation_url = @mailer_activation_url).nil?

				mailer_field_from     = @mailer_field_from.not_nil!
				mailer_activation_url = @mailer_activation_url.not_nil!

				# Once the user is created and stored, we try to contact him
				unless Process.run("password-recovery-mailer", [
					"-l", user.login,
					"-e", user.contact.email.not_nil!,
					"-t", "Password recovery email",
					"-f", mailer_field_from,
					"-u", mailer_activation_url,
					"-a", user.password_renew_key.not_nil!
					]).success?
					return Response::Error.new "cannot contact the user for password recovery"
				end
			end

			Response::PasswordRecoverySent.new user.to_public
		when Request::PasswordRecovery
			uid_or_login = request.user
			user = if uid_or_login.is_a? Int32
				@users_per_uid.get? uid_or_login.to_s
			else
				@users_per_login.get? uid_or_login
			end

			if user.nil?
				return Response::Error.new "user not found"
			end

			if user.password_renew_key == request.password_renew_key
				user.password_hash = hash_password request.new_password
			else
				return Response::Error.new "renew key not valid"
			end

			user.password_renew_key = nil

			@users_per_uid.update user.uid.to_s, user

			Response::PasswordRecovered.new user.to_public
		when Request::SearchUser
			pattern = Regex.new request.user, Regex::Options::IGNORE_CASE

			matching_users = Array(AuthD::User::Public).new

			users = @users.to_a
			users.each do |u|
				if pattern =~ u.login || u.profile.try do |profile|
						full_name = profile["full_name"]?
						if full_name.nil?
							false
						else
							pattern =~ full_name.as_s
						end
					end
					Baguette::Log.debug "#{u.login} matches #{pattern}"
					matching_users << u.to_public
				else
					Baguette::Log.debug "#{u.login} doesn't match #{pattern}"
				end
			end

			Response::MatchingUsers.new matching_users
		when Request::EditProfile
			user = get_user_from_token request.token

			return Response::Error.new "invalid user" unless user

			new_profile = request.new_profile

			profile = user.profile || Hash(String, JSON::Any).new

			@read_only_profile_keys.each do |key|
				if new_profile[key]? != profile[key]?
					return Response::Error.new "tried to edit read only key"
				end
			end

			user.profile = new_profile

			@users_per_uid.update user.uid.to_s, user

			Response::User.new user.to_public
		when Request::EditProfileContent
			user = if token = request.token
				user = get_user_from_token token

				return Response::Error.new "invalid user" unless user

				user
			elsif shared_key = request.shared_key
				return Response::Error.new "invalid shared key" if shared_key != @jwt_key

				user = request.user

				return Response::Error.new "invalid user" unless user

				user = if user.is_a? Int32
					@users_per_uid.get? user.to_s
				else
					@users_per_login.get? user
				end

				return Response::Error.new "invalid user" unless user

				user
			else
				return Response::Error.new "no token or shared_key/user pair"
			end

			new_profile = user.profile || Hash(String, JSON::Any).new

			unless request.shared_key
				@read_only_profile_keys.each do |key|
					if request.new_profile.has_key? key
						return Response::Error.new "tried to edit read only key"
					end
				end
			end

			request.new_profile.each do |key, value|
				new_profile[key] = value
			end

			user.profile = new_profile

			@users_per_uid.update user.uid.to_s, user

			Response::User.new user.to_public
		when Request::EditContacts
			user = get_user_from_token request.token

			return Response::Error.new "invalid user" unless user

			if email = request.email
				# FIXME: This *should* require checking the new mail, with
				#        a new activation key and everything else.
				user.contact.email = email
			end

			@users_per_uid.update user

			Response::UserEdited.new user.uid
		when Request::Delete
			uid_or_login = request.user
			user_to_delete = if uid_or_login.is_a? Int32
				@users_per_uid.get? uid_or_login.to_s
			else
				@users_per_login.get? uid_or_login
			end

			if user_to_delete.nil?
				return Response::Error.new "invalid user"
			end

			# Either the request comes from an admin or the user.
			# Shared key == admin, check the key.
			if key = request.shared_key
				return Response::Error.new "unauthorized (wrong shared key)" unless key == @jwt_key
			else
				login = request.login
				pass = request.password
				if login.nil? || pass.nil?
					return Response::Error.new "authentication failed (no shared key, no login)"
				end

				# authenticate the user
				begin
					user = @users_per_login.get login
				rescue e : DODB::MissingEntry
					return Response::Error.new "invalid credentials"
				end

				if user.nil?
					return Response::Error.new "invalid credentials"
				end

				if user.password_hash != hash_password pass
					return Response::Error.new "invalid credentials"
				end

				# Is the user to delete the requesting user?
				if user.uid != user_to_delete.uid
					return Response::Error.new "invalid credentials"
				end
			end

			# User or admin is now verified: let's proceed with the user deletion.
			@users_per_login.delete user_to_delete.login

			# TODO: better response
			Response::User.new user_to_delete.to_public
		else
			Response::Error.new "unhandled request type"
		end
	end

	def get_user_from_token(token : String)
		token_payload = Token.from_s(@jwt_key, token)

		@users_per_uid.get? token_payload.uid.to_s
	end

	def run
		##
		# Provides a JWT-based authentication scheme for service-specific users.
		server = IPC::Server.new "auth"
		server.base_timer = 30000 # 30 seconds
		server.timer      = 30000 # 30 seconds
		server.loop do |event|
			if event.is_a? IPC::Exception
				Baguette::Log.error "IPC::Exception"
				pp! event
				next
			end

			case event
			when IPC::Event::Timer
				Baguette::Log.debug "Timer"
			when IPC::Event::MessageReceived
				begin
					request = Request.from_ipc(event.message).not_nil!

					Baguette::Log.info "<< #{request.class.name.sub /^Request::/, ""}"

					response = handle_request request

					response.id = request.id

					server.send event.fd, response
				rescue e : MalformedRequest
					Baguette::Log.error "#{e.message}"
					Baguette::Log.error " .. type was:    #{e.ipc_type}"
					Baguette::Log.error " .. payload was: #{e.payload}"
					response =  Response::Error.new e.message
				rescue e
					Baguette::Log.error "#{e.message}"
					response = Response::Error.new e.message
				end

				Baguette::Log.info ">> #{response.class.name.sub /^Response::/, ""}"
			end
		end
	end
end

authd_storage = "storage"
authd_jwt_key = "nico-nico-nii"
authd_registrations = false
authd_require_email = false
activation_url : String? = nil
field_subject  : String? = nil
field_from     : String? = nil
read_only_profile_keys = Array(String).new

begin
	OptionParser.parse do |parser|
		parser.banner = "usage: authd [options]"

		parser.on "-s directory", "--storage directory", "Directory in which to store users." do |directory|
			authd_storage = directory
		end

		parser.on "-K file", "--key-file file", "JWT key file" do |file_name|
			authd_jwt_key = File.read(file_name).chomp
		end

		parser.on "-R", "--allow-registrations" do
			authd_registrations = true
		end

		parser.on "-E", "--require-email" do
			authd_require_email = true
		end

		parser.on "-t subject", "--subject title", "Subject of the email." do |s|
			field_subject = s
		end

		parser.on "-f from-email", "--from email", "'From:' field to use in activation email." do |f|
			field_from = f
		end

		parser.on "-u", "--activation-url url", "Activation URL." do |opt|
			activation_url = opt
		end

		parser.on "-x key", "--read-only-profile-key key", "Marks a user profile key as being read-only." do |key|
			read_only_profile_keys.push key
		end

		parser.on "-v verbosity",
			"--verbosity level",
			"Verbosity level. From 0 to 3. Default: 1" do |v|
			Baguette::Context.verbosity = v.to_i
		end


		parser.on "-h", "--help", "Show this help" do
			puts parser

			exit 0
		end
	end

	AuthD::Service.new(authd_storage, authd_jwt_key).tap do |authd|
		authd.registrations_allowed = authd_registrations
		authd.require_email         = authd_require_email
		authd.mailer_activation_url = activation_url
		authd.mailer_field_subject  = field_subject
		authd.mailer_field_from     = field_from
		authd.read_only_profile_keys = read_only_profile_keys
	end.run
rescue e : OptionParser::Exception
	Baguette::Log.error e.message
rescue e
	Baguette::Log.error "exception raised: #{e.message}"
	e.backtrace.try &.each do |line|
		STDERR << "  - " << line << '\n'
	end
end

