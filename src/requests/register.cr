class AuthD::Request
	IPC::JSON.message Register, 6 do
		property login      : String
		property password   : String
		property email      : String?                  = nil
		property phone      : String?                  = nil
		property profile    : Hash(String, JSON::Any)? = nil

		def initialize(@login, @password, @email, @phone, @profile)
		end

		def handle(authd : AuthD::Service)
			if ! authd.configuration.registrations
				return Response::Error.new "registrations not allowed"
			end

			if authd.users_per_login.get? @login
				return Response::Error.new "login already used"
			end

			if authd.configuration.require_email && @email.nil?
				return Response::Error.new "email required"
			end

			if ! @email.nil?
				# Test on the email address format.
				grok = Grok.new [ "%{EMAILADDRESS:email}" ]
				result = grok.parse @email.not_nil!
				email = result["email"]?

				if email.nil?
					return Response::Error.new "invalid email format"
				end
			end

			# In this case we should not accept its registration.
			if @password.size < 4
				return Response::Error.new "password too short"
			end

			uid = authd.new_uid
			password = authd.hash_password @password

			user = User.new uid, @login, password
			user.contact.email = @email unless @email.nil?
			user.contact.phone = @phone unless @phone.nil?

			@profile.try do |profile|
				user.profile = profile
			end

			user.date_registration = Time.local

			begin
				mailer_exe       = authd.configuration.mailer_exe
				template_name    = authd.configuration.activation_template

				u_login          = user.login
				u_email          = user.contact.email.not_nil!
				u_activation_key = user.contact.activation_key.not_nil!

				# Once the user is created and stored, we try to contact him.
				unless Process.run(mailer_exe,
						# PARAMETERS
						[ "send", template_name, u_email ],
						# ENV
						{ "LOGIN" => u_login, "TOKEN" => u_activation_key },
						true # clear environment
					).success?
					raise "cannot contact user #{u_login} address #{u_email}"
				end
			rescue e
				Baguette::Log.error "mailer: #{e}"
				return Response::Error.new "cannot contact the user (not registered)"
			end

			# add the user only if we were able to send the confirmation mail
			authd.users << user
			authd.new_uid_commit uid
			Response::UserAdded.new user.to_public
		end
	end
	AuthD.requests << Register
end
