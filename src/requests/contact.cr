class AuthD::Request
	IPC::JSON.message EditContacts, 16 do
		property token : String

		property email : String? = nil
		property phone : String? = nil

		def initialize(@token)
		end

		def handle(authd : AuthD::Service)
			user = authd.get_user_from_token @token

			return Response::Error.new "invalid user" unless user

			if email = @email
				# FIXME: This *should* require checking the new mail, with
				#        a new activation key and everything else.
				user.contact.email = email
			end

			authd.users_per_uid.update user

			Response::UserEdited.new user.uid
		end
	end
	AuthD.requests << EditContacts

	IPC::JSON.message GetContacts, 18 do
		property token : String

		def initialize(@token)
		end

		def handle(authd : AuthD::Service)
			user = authd.get_user_from_token @token

			return Response::Error.new "invalid user" unless user

			_c = user.contact

			Response::Contacts.new user.uid, _c.email, _c.phone
		end
	end
	AuthD.requests << GetContacts
end
