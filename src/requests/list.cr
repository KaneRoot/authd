class AuthD::Request
	IPC::JSON.message ListUsers, 8 do
		property token : String? = nil
		property key   : String? = nil

		def initialize(@token, @key)
		end

		def handle(authd : AuthD::Service)
			# FIXME: Lines too long, repeatedly (>80c with 4c tabs).
			@token.try do |token|
				user = authd.get_user_from_token token

				return Response::Error.new "unauthorized (user not found from token)" unless user

				# Test if the user is a moderator.
				if permissions = user.permissions["authd"]?
					if rights = permissions["*"]?
						if rights >= User::PermissionLevel::Read
						else
							raise AdminAuthorizationException.new "unauthorized (insufficient rights on '*')"
						end
					else
						raise AdminAuthorizationException.new "unauthorized (no rights on '*')"
					end
				else
					raise AdminAuthorizationException.new "unauthorized (user not in authd group)"
				end
			end

			@key.try do |key|
				return Response::Error.new "unauthorized (wrong shared key)" unless key == authd.configuration.shared_key
			end

			return Response::Error.new "unauthorized (no key nor token)" unless @key || @token

			Response::UsersList.new authd.users.to_h.map &.[1].to_public
		end
	end
	AuthD.requests << ListUsers
end
