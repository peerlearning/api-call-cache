require 'logger'
require 'redis'
require 'hashie'
require 'active_support/core_ext/object'
require 'httpclient'
require 'rack/oauth2'

require 'api_call_cache/version'

class ApiCallCache

  def self.configure
    yield self
  end

  def self.api_cache_redis_instance(redis_inst)

    raise ArgumentError, 'requires a redis instance' unless redis_inst.is_a? Redis
    @@redis_inst = redis_inst 
  end

  def self.logger_path(log_file = 'log/api_call_cache.log', rotation = 'monthly')
    @@acc_logger ||=  Logger.new(log_file, rotation)
  end

  def self.base_urls(base_urls_hash)
    @@acc_base_urls = Hashie.symbolize_keys(base_urls_hash)
  end

  def self.salt(salt_str)
     raise ArgumentError, 'requires a string as salt' if salt_str.empty?
    @@acc_salt = salt_str
  end

  def self.req_defaults
    @req_opt_defaults ||= {
                            base_url_key: '',
                            access_token: '', # TODO_FIX -- will need NetHttp etc
                            from_cache: true,
                            override_cache_expiry: nil,     # seconds. Overrides Cache-Control max-age value
                            override_params_cache_key: nil, # If provided, this value will be used
                                                            # as the 'params' part of the cache key, 
                                                            # instead of manually 'hashed_params'
                                                            #
                                                            # Useful if the api doesn't accept explicit 
                                                            # params, but is distinguished solely on the
                                                            # basis of some implicit data like 
                                                            # access_token etc
                          }
  end

  def self.get_redis
    @@redis_inst
  end

  def get_redis
    self.class.get_redis
  end

  def self.set_tz_offset(offset = '+05:30')
    @@tz_offset = offset
  end

  ##############################################################################
  # Class methods
  ##############################################################################
  def self.api_get(base_url_key, rel_path, req_params = {}, req_opts = {})
    req_opts = req_opts.merge({base_url_key: base_url_key})
    cached_api_call(:get, rel_path, req_params, req_opts)    
  end

  def self.cached_api_call(req_type, rel_path, req_params = {}, req_opts = {})
    obj = self.new
    obj.cached_api_call_core(req_type, rel_path, req_params, req_opts)
  rescue Exception => exp
    obj.acc_log_entry[:status] = 'exception'
    obj.acc_log_entry[:desc] = exp.message
    raise
  ensure
    @@acc_logger.info obj.acc_log_entry.to_a.flatten.join("\t") if @@acc_logger
  end

  def self.make_api_call(req_type, url, access_token, body=nil)
    self.new.make_api_call(req_type, url, access_token, body)
  end

  ##############################################################################
  # Instance methods
  ##############################################################################
  def cached_api_call_core(req_type, rel_path, req_params, req_opts)

    Hashie.symbolize_keys!(req_opts)
    req_opts = self.class.req_defaults.merge(req_opts)
    req_type = req_type.to_s.downcase.to_sym
    
    # Get from cache if required
    cached_body = nil

    base_url_key = req_opts[:base_url_key].to_s
    raise 'Base URL KEY not found' if base_url_key.empty?

    acc_log_entry[:api] = [base_url_key.to_s, rel_path.to_s].join('/')

    base_url = @@acc_base_urls[base_url_key.to_sym].to_s
    raise "Base URL not found for #{base_url_key}" if base_url.empty?

    cache_key       = gen_api_call_cache_key(req_type, base_url_key, 
                                             rel_path, req_params,
                                             req_opts[:override_params_cache_key])

    try_from_cache  = (req_type == :get) && req_opts[:from_cache]
    write_to_cache  = (req_type == :get)
    acc_log_entry[:cache_key] = cache_key
    cache_miss  = false

    if try_from_cache
      cached_info   = get_redis.hgetall(cache_key)
      cached_body   = cached_info['body']
      cached_status = cached_info['status'].to_i

      cache_miss = cached_body.nil?  # NOTE: 'nil?' used here on purpose instead of 'blank?'
      acc_log_entry[:status] = cache_miss ? 'miss' : 'hit'

      ttl = get_redis.ttl(cache_key).to_i.seconds
    else
      acc_log_entry[:status] = 'ignore'
    end

    if cache_miss
      
      rel_url = gen_api_call_rel_url(rel_path, req_params)

      acc_log_entry[:params_f] = req_params.to_s

      tic = ::Time.now
      api_resp = make_api_call(req_type, "#{base_url}/#{rel_url}", 
                               req_opts[:access_token])
      toc = ::Time.now

      acc_log_entry[:resp_time] = ((toc - tic)*1000).round.to_s
      acc_log_entry[:resp_code] = api_resp.status

      result_body   = api_resp.body
      result_status = api_resp.status.to_i

      if write_to_cache && api_resp.try(:ok?)
        ttl = write_to_api_cache(cache_key, api_resp, result_body, result_status,
                           req_opts[:override_cache_expiry])

        acc_log_entry[:expires_at] = (ttl.to_i.seconds.from_now).to_time.localtime(@@tz_offset).to_s
      end
    else
      # Found in cache. Using it.
      result_body   = cached_body
      result_status = cached_status
      acc_log_entry[:expires_at] = (ttl.seconds.from_now).to_time.localtime(@@tz_offset).to_s
    end

    Hashie::Mash.new(status:  result_status, 
                     body:    result_body, 
                     source:  (try_from_cache && !cache_miss) ? :cache : :api_call,
                     ok:      ::HTTP::Status::SUCCESSFUL_STATUS.include?(result_status))
  end

  def write_to_api_cache(cache_key, api_resp, cache_body, cache_status, override_cache_expiry)
    expiry = get_cache_expiry(api_resp, override_cache_expiry)

    acc_log_entry[:write_back] = 'true'

    if !expiry.zero?
      get_redis.hmset(cache_key, 'body', cache_body, 
                                 'status', cache_status)
    end

    get_redis.expire(cache_key, expiry)
    expiry
  end

  def make_api_call(req_type, url, access_token, body = nil)
    access_token = Rack::OAuth2::AccessToken::Bearer.new(access_token: access_token)
    return access_token.send(req_type, url, body)
  rescue HTTPClient::ReceiveTimeoutError => exp
    return Hashie::Mash.new(status: 408, 
                            body:   {}.to_json, 
                            ok?:    false,
                            timeout?: true)
  rescue SocketError => exp
    return Hashie::Mash.new(status: 400, 
                            body:   {error: exp.message}.to_json, 
                            ok?:    false)
  rescue Errno::ECONNREFUSED => exp
    return Hashie::Mash.new(status: 403, 
                            body:   {error: exp.message}.to_json, 
                            ok?:    false)
  end

  def gen_api_call_rel_url(rel_path, req_params)
    rel_path += '.json'
    req_params.empty? ? rel_path : [rel_path, req_params.to_query].join('?')
  end

  def gen_api_call_cache_key(_req_type, base_url_key, rel_path, req_params, hashed_params = nil)

    if hashed_params.nil? || hashed_params.empty?
      # Since params hash key hasn't been overridden using 
      plain = req_params.sort.to_h.to_query # sort req_params alphabetically
      hashed_params = OpenSSL::HMAC.hexdigest('sha256', @@acc_salt, plain)
    end

    acc_log_entry[:params_h] = hashed_params

    ['api_call_cache', 'api', base_url_key, rel_path, hashed_params].join(':')
  end


  def get_cache_expiry(response, user_expiry = nil)
    # Extract server defined TTL
    ext_ttl = nil
    if user_expiry.nil?
      cache_ctrl_hdr = response.headers['Api-Cache-Control'].to_s
      cache_ctrl_hdr = response.headers['Cache-Control'] if cache_ctrl_hdr.empty?
      cache_ctrl_hdr.split(',').map(&:strip).each do |opt|
        opts = opt.split('=')
        next if opts.first != 'max-age'
        ext_ttl = opts.last.to_i
        break
      end
    end

    expiry = user_expiry || ext_ttl || FALLBACK_TTL

    acc_log_entry[:user_ttl] =  user_expiry.to_s
    acc_log_entry[:src_ttl]  =   ext_ttl.to_s

    # Dither cache expiry
    dither_factor = 0.1

    # final expiry = given expiry + 10% variance <max 2 minutes>
    expiry += rand * ([expiry * dither_factor, 5.minutes].min)
    expiry = expiry.round

    acc_log_entry[:act_ttl] =  expiry.to_s

    expiry
  end

  attr_accessor :_acc_log_entry

  def acc_log_entry
    @_acc_log_entry ||= {
      time:         log_time,
      status:       '', # hit/miss/exception/ignore
      api:          '',
      resp_time:    '',
      resp_code:    '',
      write_back:   'false',
      user_ttl:     '', # Suggested by the internal user for overriding
      src_ttl:      '', # Suggested by the external server
      act_ttl:      '', # Actual TTL after dithering
      params_h:     '', # hashed relative path
      params_f:     '', # full form relative path
      cache_key:    '',
      desc:         '',
    }
  end

  def log_time
    time = Time.now.localtime(@@tz_offset)
    usec = time.usec.to_s.rjust(6, '0')
    time.strftime "%Y-%m-%d %H:%M:%S.#{usec} %z"
  end
end

ApiCallCache.configure do |config|
  config.base_urls({})

  config.logger_path nil

  config.salt 'api-call-cache'
  config.set_tz_offset '+05:30'
end