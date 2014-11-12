Pod::Spec.new do |s|
  s.name         = 'STLOAuth'
  s.version      = '2.0.1'
  s.summary      = 'AFNetwork 2.X + OAuth 1.0'
  s.author = {
    'Jesus Lopez' => 'inyenia@gmail.com'
  }
  s.source = {
    :git => 'https://github.com/inyenia/stl-oauth-client.git',
    :tag => "2.0.1"
  }
  s.source_files = '*.{h,m}'

  s.requires_arc = true

  s.ios.deployment_target = '6.0'
  s.osx.deployment_target = '10.8'

  s.ios.frameworks = 'MobileCoreServices', 'SystemConfiguration', 'Security', 'CoreGraphics'
  s.osx.frameworks = 'CoreServices', 'SystemConfiguration', 'Security'

  s.dependency 'AFNetworking', '~> 2.0'
end
