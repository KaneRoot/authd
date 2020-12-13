class AuthD::Response
	IPC::JSON.message Token, 1 do
		property uid    : Int32
		property token  : String
		def initialize(@token, @uid)
		end
	end
	AuthD.responses << Token
end
