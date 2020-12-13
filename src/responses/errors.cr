class AuthD::Response
	IPC::JSON.message Error, 0 do
		property reason : String? = nil
		def initialize(@reason)
		end
	end
	AuthD.responses << Error
end
