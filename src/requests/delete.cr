class AuthD::Request
	IPC::JSON.message Delete, 17 do
		# Deletion can be triggered by either an admin or the user.
		property shared_key : String? = nil

		property login      : String? = nil
		property password   : String? = nil

		property user       : String | Int32

		def initialize(@user, @login, @password)
		end
		def initialize(@user, @shared_key)
		end

		def handle(authd : AuthD::Service)
			uid_or_login = @user
			user_to_delete = if uid_or_login.is_a? Int32
				authd.users_per_uid.get? uid_or_login.to_s
			else
				authd.users_per_login.get? uid_or_login
			end

			if user_to_delete.nil?
				return Response::Error.new "invalid user"
			end

			# Either the request comes from an admin or the user.
			# Shared key == admin, check the key.
			if key = @shared_key
				return Response::Error.new "unauthorized (wrong shared key)" unless key == authd.configuration.shared_key
			else
				login = @login
				pass = @password
				if login.nil? || pass.nil?
					return Response::Error.new "authentication failed (no shared key, no login)"
				end

				# authenticate the user
				begin
					user = authd.users_per_login.get login
				rescue e : DODB::MissingEntry
					return Response::Error.new "invalid credentials"
				end

				if user.nil?
					return Response::Error.new "invalid credentials"
				end

				if user.password_hash != authd.hash_password pass
					return Response::Error.new "invalid credentials"
				end

				# Is the user to delete the requesting user?
				if user.uid != user_to_delete.uid
					return Response::Error.new "invalid credentials"
				end
			end

			# User or admin is now verified: let's proceed with the user deletion.
			authd.users_per_login.delete user_to_delete.login

			# TODO: better response
			Response::User.new user_to_delete.to_public
		end
	end
	AuthD.requests << Delete

end
