ApiCallCache.configure do |config|
  config.base_urls({})

  config.log_folder_path "log/api_call_cache.log", 'monthly'

  config.salt 'api-call-cache'
  config.offset '+05:30'
end