class AuthD::Response
	IPC::JSON.message PermissionCheck, 7 do
		property user       : Int32
		property service    : String
		property resource   : String
		property permission : ::AuthD::User::PermissionLevel
		def initialize(@service, @resource, @user, @permission)
		end
	end

	IPC::JSON.message PermissionSet, 8 do
		property user       : Int32
		property service    : String
		property resource   : String
		property permission : ::AuthD::User::PermissionLevel
		def initialize(@user, @service, @resource, @permission)
		end
	end
end
