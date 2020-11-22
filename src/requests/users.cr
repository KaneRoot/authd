class AuthD::Request
	IPC::JSON.message ValidateUser, 2 do
		property login             : String
		property activation_key    : String

		def initialize(@login, @activation_key)
		end

		def handle(authd : AuthD::Service, event : IPC::Event::Events)
			user = authd.users_per_login.get? @login

			if user.nil?
				return Response::Error.new "user not found"
			end

			if user.contact.activation_key.nil?
				return Response::Error.new "user already validated"
			end

			# remove the user contact activation key: the email is validated
			if user.contact.activation_key == @activation_key
				user.contact.activation_key = nil
			else
				return Response::Error.new "wrong activation key"
			end

			authd.users_per_uid.update user.uid.to_s, user

			Response::UserValidated.new user.to_public
		end
	end
	AuthD.requests << ValidateUser

	IPC::JSON.message GetUser, 3 do
		property user       : Int32 | String

		def initialize(@user)
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

			Response::User.new user.to_public
		end
	end
	AuthD.requests << GetUser

	IPC::JSON.message GetUserByCredentials, 4 do
		property login      : String
		property password   : String

		def initialize(@login, @password)
		end

		def handle(authd : AuthD::Service, event : IPC::Event::Events)
			user = authd.users_per_login.get? @login

			unless user
				return Response::Error.new "invalid credentials"
			end
			
			if authd.hash_password(@password) != user.password_hash
				return Response::Error.new "invalid credentials"
			end

			user.date_last_connection = Time.local

			# change the date of the last connection
			authd.users_per_uid.update user.uid.to_s, user

			Response::User.new user.to_public
		end
	end
	AuthD.requests << GetUserByCredentials
end
