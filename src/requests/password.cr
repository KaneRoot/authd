class AuthD::Request
	IPC::JSON.message UpdatePassword, 7 do
		property login      : String
		property old_password : String
		property new_password : String

		def initialize(@login, @old_password, @new_password)
		end

		def handle(authd : AuthD::Service, event : IPC::Event::Events)
			user = authd.users_per_login.get? @login

			unless user
				return Response::Error.new "invalid credentials"
			end

			if authd.hash_password(@old_password) != user.password_hash
				return Response::Error.new "invalid credentials"
			end

			user.password_hash = authd.hash_password @new_password

			authd.users_per_uid.update user.uid.to_s, user

			Response::UserEdited.new user.uid
		end
	end
	AuthD.requests << UpdatePassword

	IPC::JSON.message PasswordRecovery, 11 do
		property user               : Int32 | String
		property password_renew_key : String
		property new_password       : String

		def initialize(@user, @password_renew_key, @new_password)
		end

		def handle(authd : AuthD::Service, event : IPC::Event::Events)
			uid_or_login = @user
			user = if uid_or_login.is_a? Int32
				authd.users_per_uid.get? uid_or_login.to_s
			else
				authd.users_per_login.get? uid_or_login
			end

			if user.nil?
				return Response::Error.new "user not found"
			end

			if user.password_renew_key == @password_renew_key
				user.password_hash = authd.hash_password @new_password
			else
				return Response::Error.new "renew key not valid"
			end

			user.password_renew_key = nil

			authd.users_per_uid.update user.uid.to_s, user

			Response::PasswordRecovered.new user.to_public
		end
	end
	AuthD.requests << PasswordRecovery

	IPC::JSON.message AskPasswordRecovery, 12 do
		property user       : Int32 | String
		property email      : String

		def initialize(@user, @email)
		end

		def handle(authd : AuthD::Service, event : IPC::Event::Events)
			uid_or_login = @user
			user = if uid_or_login.is_a? Int32
				authd.users_per_uid.get? uid_or_login.to_s
			else
				authd.users_per_login.get? uid_or_login
			end

			if user.nil?
				return Response::Error.new "no such user"
			end

			if user.contact.email != @email
				# Same error as when users are not found.
				return Response::Error.new "no such user"
			end

			user.password_renew_key = UUID.random.to_s

			authd.users_per_uid.update user.uid.to_s, user

			unless (activation_url = authd.configuration.activation_url).nil?

				field_from     = authd.configuration.field_from.not_nil!
				activation_url = authd.configuration.activation_url.not_nil!

				# Once the user is created and stored, we try to contact him

				if authd.configuration.print_password_recovery_parameters
					pp! user.login,
						user.contact.email.not_nil!,
						field_from,
						activation_url,
						user.password_renew_key.not_nil!
				end

				unless Process.run("password-recovery-mailer", [
					"-l", user.login,
					"-e", user.contact.email.not_nil!,
					"-t", "Password recovery email",
					"-f", field_from,
					"-u", activation_url,
					"-a", user.password_renew_key.not_nil!
					]).success?

					return Response::Error.new "cannot contact the user for password recovery"
				end
			end

			Response::PasswordRecoverySent.new user.to_public
		end
	end
	AuthD.requests << AskPasswordRecovery
end
