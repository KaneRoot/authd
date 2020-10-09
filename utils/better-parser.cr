require "option_parser"

opt_authd_admin = -> (parser : OptionParser) {
	parser.on "-k file", "--key-file file", "Read the authd shared key from a file." do |file|
		Context.shared_key  = File.read(file).chomp
		Baguette::Log.info "Key for admin operations: #{Context.shared_key}."
	end
}

# frequently used functions
opt_authd_login = -> (parser : OptionParser) {
	parser.on "-l LOGIN", "--login LOGIN", "Authd user login." do |login|
		Context.authd_login = login
		Baguette::Log.info "User login for authd: #{Context.authd_login}."
	end
	parser.on "-p PASSWORD", "--password PASSWORD", "Authd user password." do |password|
		Context.authd_pass = password
		Baguette::Log.info "User password for authd: #{Context.authd_pass}."
	end
}

opt_help = -> (parser : OptionParser) {
	parser.on "help", "Prints this help message." do
		puts parser
		exit 0
	end
}

opt_profile = -> (parser : OptionParser) {
	parser.on "-P file", "--profile file", "Read the user profile from a file." do |file|
		Context.user_profile = JSON.parse(File.read file).as_h
		Baguette::Log.info "Reading the user profile: #{Context.user_profile}."
	end
}

opt_phone = -> (parser : OptionParser) {
	parser.on "-n phone", "--phone-number num", "Phone number." do |phone|
		Context.phone = phone
		Baguette::Log.info "Reading the user phone number: #{Context.phone}."
	end
}

opt_email = -> (parser : OptionParser) {
	parser.on "-e email", "--email address", "Email address." do |email|
		Context.email = email
		Baguette::Log.info "Reading the user email address: #{Context.email}."
	end
}


# Unrecognized parameters are used to create commands with multiple arguments.
# Example: user add _login email phone_
# Here, login, email and phone are unrecognized arguments.
# Still, the "user add" command expect them.
unrecognized_args_to_context_args = -> (parser : OptionParser, n_expected_args : Int32) {
	# With the right args, these will be interpreted as serialized data.
	parser.unknown_args do |args|
		if args.size != n_expected_args
			Baguette::Log.error "#{parser}"
			exit 1
		end
		args.each do |arg|
			Baguette::Log.debug "Unrecognized argument: #{arg} (adding to Context.args)"
			if Context.args.nil?
				Context.args = Array(String).new
			end
			Context.args.not_nil! << arg
		end
	end
}

parser = OptionParser.new do |parser|
	parser.banner = "usage: #{PROGRAM_NAME} command help"
	parser.on "-v verbosity", "--verbosity v", "Verbosity. From 0 to 4 (debug)." do |v|
		Baguette::Context.verbosity = v.to_i
		Baguette::Log.info "verbosity = #{v}"
	end
	parser.on "-h", "--help", "Prints this help message." do
		puts "usage: #{PROGRAM_NAME} command help"
		puts parser
		exit 0
	end

	parser.on "user", "Operations on users." do
		parser.banner = "Usage: user [add | mod | delete | validate | search | get | recover | register ]"

		parser.on "add", "Adding a user to the DB." do
			parser.banner = "usage: user add login email phone [-P profile] [opt]"
			Baguette::Log.info "Adding a user to the DB."
			Context.command = "user-add"
			opt_authd_admin.call parser
			opt_profile.call parser
			opt_email.call parser
			opt_phone.call parser
			opt_help.call parser
			# login email phone
			unrecognized_args_to_context_args.call parser, 3
		end

		parser.on "mod", "Modify a user account." do
			parser.banner = "Usage: user mod userid [-e email|-n phone|-P profile] [opt]"
			Baguette::Log.info "Modify a user account."
			Context.command = "user-mod"
			opt_authd_admin.call parser
			opt_email.call parser
			opt_phone.call parser
			opt_profile.call parser
			opt_help.call parser
			# userid
			unrecognized_args_to_context_args.call parser, 1
		end

		parser.on "delete", "Remove user." do
			parser.banner = "Usage: user delete userid [opt]"
			Baguette::Log.info "Remove user."
			Context.command = "user-delete"
			# You can either be the owner of the account, or an admin.
			opt_authd_login.call parser
			opt_authd_admin.call parser
			opt_help.call parser
			# userid
			unrecognized_args_to_context_args.call parser, 1
		end

		parser.on "validate", "Validate user." do
			parser.banner = "Usage: user validate login activation-key [opt]"
			Baguette::Log.info "Validate user."
			Context.command = "user-validate"
			# No need to be authenticated.
			opt_help.call parser
			# login activation-key
			unrecognized_args_to_context_args.call parser, 2
		end

		parser.on "get", "Get user info." do
			parser.banner = "Usage: user get login [opt]"
			Baguette::Log.info "Get user info."
			Context.command = "user-get"
			# No need to be authenticated.
			opt_help.call parser
			# login
			unrecognized_args_to_context_args.call parser, 1
		end

		parser.on "search", "Search user." do
			parser.banner = "Usage: user recover login [opt]"
			Baguette::Log.info "Search user."
			Context.command = "user-search"
			# No need to be authenticated.
			opt_help.call parser
			# login
			unrecognized_args_to_context_args.call parser, 1
		end

		parser.on "recover", "Recover user password." do
			parser.banner = "Usage: user recover login email [opt]"
			Baguette::Log.info "Recover user password."
			Context.command = "user-recovery"
			# No need to be authenticated.
			opt_help.call parser
			# login email
			unrecognized_args_to_context_args.call parser, 2
		end


		# Do not require to be admin.
		parser.on "register", "Register a user (requires activation)." do
			parser.banner = "Usage: user register login email phone [-P profile] [opt]"
			Baguette::Log.info "Register a user (requires activation)."
			Context.command = "user-registration"
			# These options shouldn't be used here,
			# email and phone parameters are mandatory.
			# opt_email.call parser
			# opt_phone.call parser
			opt_profile.call parser
			opt_help.call parser
			# login email phone
			unrecognized_args_to_context_args.call parser, 3
		end
	end

	parser.on "permission", "Permissions management." do
		parser.banner = "Usage: permissions [check | set]"
		parser.on "set", "Set permissions." do
			parser.banner = <<-END
  usage: permission set user  application     resource  permission
example: permission set 1002  my-application  chat      read

permission list: none read edit admin
END
			Baguette::Log.info "Set permissions."
			Context.command = "permission-set"
			opt_authd_admin.call parser
			opt_help.call parser
			# userid application resource permission
			unrecognized_args_to_context_args.call parser, 4
		end

		parser.on "check", "Check permissions." do
			parser.banner = <<-END
  usage: permission check user application    resource
example: permission check 1002 my-application chat

permission list: none read edit admin
END
			Baguette::Log.info "Check permissions."
			Context.command = "permission-check"
			opt_authd_admin.call parser
			opt_help.call parser
			# userid application resource
			unrecognized_args_to_context_args.call parser, 3
		end
	end

	parser.unknown_args do |args|
		if args.size > 0
			Baguette::Log.warning "Unknown args: #{args}"
		end
	end

#	parser.on "-X user-password", "--user-password pass", "Read the new user password." do |pass|
#		password = pass
#	end

end


parser.parse
