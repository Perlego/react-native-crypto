require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "react-native-crypto"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.description  = <<-DESC
                  react-native-crypto
                   DESC
  s.homepage     = "https://github.com/Perlego/react-native-crypto"
  s.license      = "MIT"
  # s.license    = { :type => "MIT", :file => "FILE_LICENSE" }
  s.authors      = { "Perlego" => "ios-devs@perlego.com" }
  s.platforms    = { :ios => "9.0" }
  s.source       = { :git => "https://github.com/Perlego/react-native-crypto.git", :tag => "#{s.version}" }

  s.source_files = "ios/**/*.{h,m,swift}"
  s.requires_arc = true

  s.dependency "React"
  # ...
  # s.dependency "..."
end

