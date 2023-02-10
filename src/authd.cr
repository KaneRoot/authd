require "uuid"
require "option_parser"
require "openssl"
require "colorize"
require "jwt"
require "grok"

require "dodb"
require "ipc"

require "baguette-crystal-base"

# Allows get configuration from a provided file.
# See Baguette::Configuration::Base.get
class Baguette::Configuration
	class Auth < IPC
		include YAML::Serializable

		property login           : String? = nil
		property pass            : String? = nil
		property shared_key      : String  = "nico-nico-nii" # Default authd key, as per the specs. :eyes:
		property shared_key_file : String? = nil

		def initialize
		end
	end
end

# Token and user classes.
require "./authd/token.cr"
require "./authd/user.cr"

# Requests and responses.
require "./authd/exceptions"

# Requests and responses.
require "./network"

# Functions to request the authd server.
require "./authd/client.cr"
