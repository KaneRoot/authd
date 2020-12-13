class AuthD::Response
	IPC::JSON.message PasswordRecoverySent, 9 do
		property user   : ::AuthD::User::Public
		def initialize(@user)
		end
	end
	AuthD.responses << PasswordRecoverySent

	IPC::JSON.message PasswordRecovered, 10 do
		property user   : ::AuthD::User::Public
		def initialize(@user)
		end
	end
	AuthD.responses << PasswordRecovered
end
