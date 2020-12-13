class AuthD::Response
	IPC::JSON.message Contacts, 12 do
		property user : Int32
		property email : String? = nil
		property phone : String? = nil
		def initialize(@user, @email, @phone)
		end
	end
	AuthD.responses << Contacts
end
