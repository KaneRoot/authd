class AuthD::Request
	IPC::JSON.message AddUser, 1 do
		# Only clients that have the right shared key will be allowed
		# to create users.
		property shared_key : String

		property login      : String
		property password   : String
		property email      : String?                  = nil
		property phone      : String?                  = nil
		property profile    : Hash(String, JSON::Any)? = nil

		def initialize(@shared_key, @login, @password, @email, @phone, @profile)
		end

		def handle(authd : AuthD::Service)
			# No verification of the users' informations when an admin adds it.
			# No mail address verification.
			if @shared_key != authd.configuration.shared_key
				return Response::Error.new "invalid authentication key"
			end

			if authd.users_per_login.get? @login
				return Response::Error.new "login already used"
			end

			if authd.configuration.require_email && @email.nil?
				return Response::Error.new "email required"
			end

			password_hash = authd.hash_password @password

			uid = authd.new_uid

			user = User.new uid, @login, password_hash
			user.contact.email = @email unless @email.nil?
			user.contact.phone = @phone unless @phone.nil?

			@profile.try do |profile|
				user.profile = profile
			end

			# We consider adding the user as a registration
			user.date_registration = Time.local

			authd.users << user
			authd.new_uid_commit uid
			Response::UserAdded.new user.to_public
		end
	end
	AuthD.requests << AddUser


	IPC::JSON.message ModUser, 5 do
		property shared_key : String

		property user       : Int32 | String
		property password   : String? = nil
		property email      : String? = nil
		property phone      : String? = nil
		property avatar     : String? = nil

		def initialize(@shared_key, @user)
		end

		def handle(authd : AuthD::Service)
			if @shared_key != authd.configuration.shared_key
				return Response::Error.new "invalid authentication key"
			end

			uid_or_login = @user
			user = if uid_or_login.is_a? Int32
				authd.users_per_uid.get? uid_or_login.to_s
			else
				authd.users_per_login.get? uid_or_login
			end

			unless user
				return Response::Error.new "user not found"
			end

			@password.try do |s|
				user.password_hash = authd.hash_password s
			end

			@email.try do |email|
				user.contact.email = email
			end

			@phone.try do |phone|
				user.contact.phone = phone
			end

			authd.users_per_uid.update user.uid.to_s, user

			Response::UserEdited.new user.uid
		end
	end
	AuthD.requests << ModUser
end
