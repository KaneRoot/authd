class AuthD::Request
	IPC::JSON.message CheckPermission, 9 do
		property shared_key : String? = nil
		property token      : String? = nil

		property user       : Int32 | String
		property service    : String
		property resource   : String

		def initialize(@shared_key, @user, @service, @resource)
		end

		def handle(authd : AuthD::Service)
			authorized = false

			if key = @shared_key
				if key == authd.configuration.shared_key
					authorized = true
				else
					return Response::Error.new "invalid key provided"
				end
			end

			if token = @token
				user = authd.get_user_from_token token

				if user.nil?
					return Response::Error.new "token does not match user"
				end

				if user.login != @user && user.uid != @user
					return Response::Error.new "token does not match user"
				end

				authorized = true
			end

			unless authorized
				return Response::Error.new "unauthorized"
			end

			user = case u = @user
			when .is_a? Int32
				authd.users_per_uid.get? u.to_s
			else
				authd.users_per_login.get? u
			end

			if user.nil?
				return Response::Error.new "no such user"
			end

			service = @service
			service_permissions = user.permissions[service]?

			if service_permissions.nil?
				return Response::PermissionCheck.new service, @resource, user.uid, User::PermissionLevel::None
			end

			resource_permissions = service_permissions[@resource]?

			if resource_permissions.nil?
				return Response::PermissionCheck.new service, @resource, user.uid, User::PermissionLevel::None
			end

			return Response::PermissionCheck.new service, @resource, user.uid, resource_permissions
		end
	end
	AuthD.requests << CheckPermission

	IPC::JSON.message SetPermission, 10 do
		property shared_key : String

		property user       : Int32 | String
		property service    : String
		property resource   : String
		property permission : ::AuthD::User::PermissionLevel

		def initialize(@shared_key, @user, @service, @resource, @permission)
		end

		def handle(authd : AuthD::Service)
			unless @shared_key == authd.configuration.shared_key
				return Response::Error.new "unauthorized"
			end

			user = authd.users_per_uid.get? @user.to_s

			if user.nil?
				return Response::Error.new "no such user"
			end

			service = @service
			service_permissions = user.permissions[service]?

			if service_permissions.nil?
				service_permissions = Hash(String, User::PermissionLevel).new
				user.permissions[service] = service_permissions
			end

			if @permission.none?
				service_permissions.delete @resource
			else
				service_permissions[@resource] = @permission
			end

			authd.users_per_uid.update user.uid.to_s, user

			Response::PermissionSet.new user.uid, service, @resource, @permission
		end
	end
	AuthD.requests << SetPermission
end
