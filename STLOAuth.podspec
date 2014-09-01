Pod::Spec.new do |s|
  s.name         = 'STLOAuth'
  s.version      = '1.0.3'
  s.summary      = 'AFNetwork + OAuth 1.0'
  s.author = {
    'Jesus Lopez' => 'inyenia@gmail.com'
  }
  s.source = {
    :git => 'https://github.com/inyenia/stl-oauth-client.git',
    :tag => "1.0.3"
  }
  s.requires_arc = true
  s.source_files = '*.{h,m}'
end
