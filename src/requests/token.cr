class AuthD::Request
	IPC::JSON.message GetToken, 0 do
		property login      : String
		property password   : String

		def initialize(@login, @password)
		end

		def handle(authd : AuthD::Service, event : IPC::Event::Events)
			begin
				user = authd.users_per_login.get @login
			rescue e : DODB::MissingEntry
				return Response::Error.new "invalid credentials"
			end

			if user.nil?
				return Response::Error.new "invalid credentials"
			end

			if user.password_hash != authd.hash_password @password
				return Response::Error.new "invalid credentials"
			end

			user.date_last_connection = Time.local
			token = user.to_token

			# change the date of the last connection
			authd.users_per_uid.update user.uid.to_s, user

			Response::Token.new (token.to_s authd.configuration.shared_key), user.uid
		end
	end
	AuthD.requests << GetToken
end
