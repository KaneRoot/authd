class AuthD::Response
	IPC::JSON.message User, 2 do
		property user   : ::AuthD::User::Public
		def initialize(@user)
		end
	end

	IPC::JSON.message UserAdded, 3 do
		property user   : ::AuthD::User::Public
		def initialize(@user)
		end
	end

	IPC::JSON.message UserEdited, 4 do
		property uid    : Int32
		def initialize(@uid)
		end
	end

	IPC::JSON.message UserValidated, 5 do
		property user   : ::AuthD::User::Public
		def initialize(@user)
		end
	end

	IPC::JSON.message UsersList, 6 do
		property users  : Array(::AuthD::User::Public)
		def initialize(@users)
		end
	end

	IPC::JSON.message MatchingUsers, 11 do
		property users  : Array(::AuthD::User::Public)
		def initialize(@users)
		end
	end
end
