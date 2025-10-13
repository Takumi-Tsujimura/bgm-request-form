require 'bundler/setup'
Bundler.require
require 'sinatra/reloader' if development?
require 'securerandom'
require 'uri'
require 'json'
require 'net/http'
require 'open-uri'
require 'base64'
require 'dotenv/load'
require 'cgi'
require 'rqrcode'
require 'pony'
require './models'

enable :sessions
use Rack::MethodOverride


configure do
  
  Dotenv.load

  set :client_id, ENV['CLIENT_ID']
  set :client_secret, ENV['CLIENT_SECRET']
  set :redirect_uri, ENV['REDIRECT_URI'] || 'http://localhost:8888/callback'
end


#Auth認証関連
def refresh_user_access_token(user)
  return if user.spotify_refresh_token.nil?

  uri = URI('https://accounts.spotify.com/api/token')
  auth_header = "Basic #{Base64.strict_encode64("#{settings.client_id}:#{settings.client_secret}")}"

  req = Net::HTTP::Post.new(uri)
  req['Authorization'] = auth_header
  req['Content-Type'] = 'application/x-www-form-urlencoded'
  req.set_form_data(
    grant_type: 'refresh_token',
    refresh_token: user.spotify_refresh_token
  )

  res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) { |http| http.request(req) }
  if res.is_a?(Net::HTTPSuccess)
    token_data = JSON.parse(res.body)
    
    user.assign_attributes(
      spotify_access_token: token_data['access_token'],
      spotify_expires_at: Time.now + token_data['expires_in'].to_i
    )
    success = user.save(validate: false)

    puts "[INFO] トークン更新: #{user.id} 成功=#{success}"
    puts "[ERROR] 更新失敗: #{user.errors.full_messages.join(', ')}" unless success
  else
    puts "[ERROR] Spotifyトークンの更新に失敗: #{res.code} #{res.body}"
  end
end

def refresh_access_token
  return if session[:refresh_token].nil?

  uri = URI('https://accounts.spotify.com/api/token')
  auth_header = "Basic #{Base64.strict_encode64("#{settings.client_id}:#{settings.client_secret}")}"

  req = Net::HTTP::Post.new(uri)
  req['Authorization'] = auth_header
  req['Content-Type'] = 'application/x-www-form-urlencoded'
  req.set_form_data(
    grant_type: 'refresh_token',
    refresh_token: session[:refresh_token]
  )

  res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) { |http| http.request(req) }

  if res.is_a?(Net::HTTPSuccess)
    token_data = JSON.parse(res.body)

    # セッションに反映
    session[:access_token] = token_data['access_token']
    session[:expires_in] = Time.now + token_data['expires_in'].to_i

    # ユーザー情報にも保存（データベース更新）
    user = User.find_by(id: session[:user_id])
    if user
      user.update(
        spotify_access_token: token_data['access_token'],
        spotify_expires_at: session[:expires_in]
      )
    end
  else
    puts "[ERROR] セッション用Spotifyトークンの更新失敗: #{res.code} #{res.body}"
  end
end

def ensure_valid_token
  if session[:expires_in] && Time.now > session[:expires_in]
    refresh_access_token
  end
end

def get_user_profile
  ensure_valid_token
  uri = URI('https://api.spotify.com/v1/me')
  req = Net::HTTP::Get.new(uri)
  req['Authorization'] = "Bearer #{session[:access_token]}"

  res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) { |http| http.request(req) }
  res.is_a?(Net::HTTPSuccess) ? JSON.parse(res.body) : nil
end

get '/auth' do
  state = SecureRandom.hex(8)
  session[:state] = state
  session[:user] = {id: 1, name: "test_user"}

  scope = 'user-read-private user-read-email playlist-modify-public playlist-modify-private'
  query_params = {
    response_type: 'code',
    client_id: settings.client_id,
    scope: scope,
    redirect_uri: settings.redirect_uri,
    state: state,
    show_dialog: true
  }

  redirect "https://accounts.spotify.com/authorize?" + URI.encode_www_form(query_params)
end

get '/callback' do
  code = params[:code]
  state = params[:state]
  return redirect '/' if state != session[:state]

  # アクセストークン取得
  uri = URI('https://accounts.spotify.com/api/token')
  auth_header = "Basic #{Base64.strict_encode64("#{settings.client_id}:#{settings.client_secret}")}"
  
  req = Net::HTTP::Post.new(uri)
  req['Authorization'] = auth_header
  req['Content-Type'] = 'application/x-www-form-urlencoded'
  req.set_form_data(
    grant_type: 'authorization_code',
    code: code,
    redirect_uri: settings.redirect_uri
  )
  
  res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) { |http| http.request(req) }
  
  unless res.is_a?(Net::HTTPSuccess)
    puts "[ERROR] トークン取得失敗: #{res.code} #{res.body}"
    return redirect '/?error=token_fetch_failed'
  end
  
  token_data = JSON.parse(res.body)
  puts "[DEBUG] トークン取得成功: #{token_data}"
  
  access_token = token_data['access_token']
  refresh_token = token_data['refresh_token']
  expires_at = Time.now + token_data['expires_in'].to_i

  # Spotifyユーザー情報を取得
  profile_uri = URI('https://api.spotify.com/v1/me')
  profile_req = Net::HTTP::Get.new(profile_uri)
  profile_req['Authorization'] = "Bearer #{access_token}"
  profile_res = Net::HTTP.start(profile_uri.hostname, profile_uri.port, use_ssl: true) { |http| http.request(profile_req) }

  return redirect '/' unless profile_res.is_a?(Net::HTTPSuccess)
  spotify_user = JSON.parse(profile_res.body)
  spotify_uid = spotify_user['id']
  spotify_display_name = spotify_user['display_name']

  # 新規登録処理（セッションに signup_params があるとき）
  if session[:signup_params]
    signup = session.delete(:signup_params)

    user = User.new(
      first_name: signup[:first_name],
      last_name: signup[:last_name],
      nick_name: signup[:nick_name],
      mail: signup[:mail],
      password: signup[:password],
      spotify_uid: spotify_uid,
      spotify_access_token: access_token,
      spotify_refresh_token: refresh_token,
      spotify_expires_at: expires_at,
      spotify_display_name: spotify_display_name
    )

    if user.save
      session[:user_id] = user.id

      session[:access_token] = access_token
      session[:refresh_token] = refresh_token
      session[:expires_in] = expires_at
      
      send_signup_confirmation_mail(user)
      
      redirect '/login_form'
    else
      return "ユーザー登録に失敗しました: #{user.errors.full_messages.join(', ')}"
    end
  elsif session[:user_id]
    user = User.find_by(id: session[:user_id])
  
    if user
      user.assign_attributes(
        spotify_uid: spotify_uid,
        spotify_access_token: access_token,
        spotify_refresh_token: refresh_token,
        spotify_expires_at: expires_at,
        spotify_display_name: spotify_display_name
      )
  
      if user.save(validate: false)
        # セッションにも最新トークンを反映
        session[:access_token] = access_token
        session[:refresh_token] = refresh_token
        session[:expires_in] = expires_at
  
        puts "[INFO] Spotify連携更新成功: ユーザーID #{user.id}"
        redirect '/admin'
      else
        puts "[ERROR] Spotify連携情報の保存に失敗: #{user.errors.full_messages.join(', ')}"
        return "Spotify情報の更新に失敗しました。"
      end
    else
      return "ログイン中のユーザーが見つかりませんでした。"
    end
  else
    redirect '/admin'
  end
end


##users
get '/' do
  erb :home
end

get '/form/:form_key' do
  @form = Form.find_by(form_key: params[:form_key])
  @success_message = session.delete(:success_message)
  
  today_deadline = Date.today - 1
  deadline = @form.deadline.to_date rescue nil

  if deadline && deadline <= today_deadline
    redirect '/error'
  end

  erb :'users/show', layout: :'users/layout'
end

get 'error' do
  erb :'users/error.erb', layout: false
end

get '/search/:form_key' do
  @form = Form.find_by(form_key: params[:form_key])
  keyword = params[:keyword]
  return redirect "/form/\#{params[:form_key]}" if keyword.nil? || keyword.strip.empty?

  form_owner = @form.user
  refresh_user_access_token(form_owner) if form_owner.spotify_expires_at && form_owner.spotify_expires_at < Time.now

  token = form_owner.spotify_access_token
  return "このフォームの管理者がSpotifyにログインしていません" if token.nil? || token.empty?

  uri = URI("https://api.spotify.com/v1/search?" + URI.encode_www_form(q: keyword, type: 'track'))
  req = Net::HTTP::Get.new(uri)
  req['Authorization'] = "Bearer #{token}"

  res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) { |http| http.request(req) }
  return "Spotify APIエラー: \#{res.code} - \#{res.body}" unless res.is_a?(Net::HTTPSuccess)

  @items = JSON.parse(res.body)['tracks']['items']
  return "検索結果なし。" if @items.nil? || @items.empty?

  erb :'users/list', layout: :'users/layout'
end

get '/form/:form_key/req_form' do
  puts "[DEBUG] form_key: #{params[:form_key]}"
  @form = Form.find_by(form_key: params[:form_key])

  if @form.nil?
    return erb :error, locals: { message: "フォームが見つかりませんでした。" }
  end

  case @form.form_type
  when 'general'
    erb :'users/req_form_for_general', layout: false
  when 'school'
    erb :'users/req_form_for_school', layout: false
  else
    erb :error, locals: { message: "不正なフォームタイプです。" }
  end
end

post '/submit_request/:form_key' do
  @form = Form.find_by(form_key: params[:form_key])
  halt(404, "フォームが見つかりません") unless @form
  
  user_name = params[:user_name]
  track_name = params[:track_name]
  track_artists = params[:track_artists]
  track_id = params[:track_id]

  grade = params[:grade]
  class_name = params[:class_name]   
  number = params[:number]
  
  return "エラー: トラックIDが指定されていません" if track_id.nil? || track_id.strip.empty?
  
  form_owner = @form.user
  refresh_user_access_token(form_owner) if form_owner.spotify_expires_at && form_owner.spotify_expires_at < Time.now
  
  token = form_owner.spotify_access_token
  return "エラー: このフォームの管理者がSpotifyにログインしていません" if token.nil? || token.empty?
  
  playlist_uri = URI("https://api.spotify.com/v1/playlists/#{@form.playlist_id}/tracks?fields=items(track(id)),next&limit=100")
  headers = { 'Authorization' => "Bearer #{token}" }
  
  duplicate_found = false
  loop do
    req = Net::HTTP::Get.new(playlist_uri, headers)
    res = Net::HTTP.start(playlist_uri.hostname, playlist_uri.port, use_ssl: true) { |http| http.request(req) }

    unless res.is_a?(Net::HTTPSuccess)
      return "Spotify APIエラー（取得失敗）: #{res.code} - #{res.body}"
    end

    body = JSON.parse(res.body)
    track_ids = body["items"].map { |item| item.dig("track", "id") }
    if track_ids.include?(track_id)
      duplicate_found = true
      break
    end

    next_url = body["next"]
    break unless next_url
    playlist_uri = URI(next_url)
  end

  # リクエストを保存する共通処理
  def save_request(form, user_name, track_name, track_artists, track_id, grade, class_name, number)
    Request.create(
      form_key: form.form_key,
      form_id: form.id,
      user_name: user_name,
      track_name: track_name,
      track_artists: track_artists,
      track_id: track_id,
      grade: grade,
      class_name: class_name, 
      number: number
    )
  end

  if duplicate_found
    request = save_request(@form, user_name, track_name, track_artists, track_id, grade, class_name, number)
    puts "=== リクエスト保存 (重複)" 
    puts request.inspect
    session[:success_message] = "リクエストが完了しました"
    redirect "/form/#{params[:form_key]}"
  end

  # 重複してない場合 → Spotifyに追加
  uri = URI("https://api.spotify.com/v1/playlists/#{@form.playlist_id}/tracks")
  request_body = {
    "uris" => ["spotify:track:#{track_id}"],
    "position" => 0
  }.to_json

  req = Net::HTTP::Post.new(uri)
  req['Authorization'] = "Bearer #{token}"
  req['Content-Type'] = 'application/json'
  req.body = request_body

  res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) { |http| http.request(req) }

  if res.is_a?(Net::HTTPSuccess)
    request = save_request(@form, user_name, track_name, track_artists, track_id, grade, class_name, number)
    puts "=== リクエスト保存 (追加成功)"
    puts request.inspect
    session[:success_message] = "リクエストが完了しました"
    redirect "/form/#{params[:form_key]}"
  else
    "Spotify APIエラー: #{res.code} - #{res.body}"
  end
end


##admin
get '/admin' do
  @title = "管理者ページ"
  # @forms = Form.all
  access_token = session[:access_token]
  
  if session[:user_id].nil?
    redirect '/login_form'
  end
  
  @current_user = User.find(session[:user_id])
  @forms = Form.where(user_id: session[:user_id])
  
  erb :'admin/form_list', layout: :'admin/layout'
end

#フォーム作成、編集
get '/form_templates/new' do
  @title = "新規フォーム作成"
  ensure_valid_token  # トークンの有効性を確認・更新
  token = session[:access_token]

  if token.nil? || token.empty?
    return "エラー: Spotify API トークンが取得できていません。ログインしてください。"
  end

  uri = URI("https://api.spotify.com/v1/me/playlists")
  req = Net::HTTP::Get.new(uri)
  req['Authorization'] = "Bearer #{token}"

  res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) { |http| http.request(req) }

  if res.is_a?(Net::HTTPSuccess)
    begin
      @playlists = JSON.parse(res.body)["items"]
    rescue JSON::ParserError => e
      return "エラー: JSON のパースに失敗しました。レスポンス: #{res.body}"
    end
  else
    redirect '/admin'
  end

  erb :'admin/create_form', layout: :'admin/layout'
end

get '/add_playlist_form' do
  user = User.find(session[:user_id])
  @spotify_user_id = user.spotify_uid
  
  erb :'admin/add_playlist_form', layout: false
end

post '/create_playlist' do
  playlist_name = params[:playlist_name]

  form_owner = User.find(session[:user_id])

  if form_owner.spotify_expires_at.nil? || Time.now > form_owner.spotify_expires_at
    refresh_user_access_token(form_owner)
  end

  access_token = form_owner.spotify_access_token
  spotify_user_id = form_owner.spotify_uid

  uri = URI("https://api.spotify.com/v1/users/#{spotify_user_id}/playlists")
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true

  request = Net::HTTP::Post.new(uri.request_uri)
  request['Authorization'] = "Bearer #{access_token}"
  request['Content-Type'] = 'application/json'
  request.body = {
    name: playlist_name,
    description: "New playlist created by TuneBox!",
    public: false
  }.to_json

  response = http.request(request)

  if response.code == "201"
    playlist_info = JSON.parse(response.body)
    playlist_id = playlist_info["id"]

    session[:new_playlist_id] = playlist_id

    redirect '/form_templates/new'  
  else
    "プレイリスト作成に失敗しました: #{response.body}"
  end
end

post '/form_templates' do
  user_id = session[:user_id]
  unless user_id
    redirect '/login_form'
  end

  form_name = params[:form_name]
  playlist_id = params[:playlist_id]
  deadline = params[:deadline]
  form_type = params[:form_type]
  
  deadline = nil if deadline.nil? || deadline.strip.empty?

  form = Form.new(
    form_name: form_name,
    playlist_id: playlist_id,
    deadline: deadline,
    form_type: form_type,
    user_id: user_id
  )

  if form.save
    puts "=== フォーム作成成功 ==="
    puts "form_id: #{form.id}"
    puts "form_key(UUID): #{form.form_key}"
    redirect '/admin'
  else
    erb :error, locals: { message: "フォームの保存に失敗しました。" }
  end
end

get '/forms/:form_key/edit' do
  @title = "フォーム編集"

  @form = Form.find_by(form_key: params[:form_key])
  
  ensure_valid_token  # トークンの有効性を確認・更新
  token = session[:access_token]

  if token.nil? || token.empty?
    return "エラー: Spotify API トークンが取得できていません。ログインしてください。"
  end

  uri = URI("https://api.spotify.com/v1/me/playlists")
  req = Net::HTTP::Get.new(uri)
  req['Authorization'] = "Bearer #{token}"

  res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) { |http| http.request(req) }

  if res.is_a?(Net::HTTPSuccess)
    begin
      @playlists = JSON.parse(res.body)["items"]
    rescue JSON::ParserError => e
      return "エラー: JSON のパースに失敗しました。レスポンス: #{res.body}"
    end
  else
    return "Spotify API エラー: #{res.code} - #{res.message} - #{res.body}"
  end
  
  erb :'admin/edit', layout: :'admin/layout'
end

patch '/forms/:form_key' do
  form = Form.find_by(form_key: params[:form_key])
  halt 404, "フォームが見つかりません" unless form

  deadline = params[:deadline]
  deadline = nil if deadline.nil? || deadline.strip.empty?  

  form.update(
    form_name: params[:form_name],
    playlist_id: params[:playlist_id],
    deadline: deadline,
    form_type: params[:form_type]  
  )

  redirect '/admin'
end

delete '/forms/:form_key' do
  form = Form.find_by(form_key: params[:form_key])
  halt 404, "フォームが見つかりません" unless form
    
  form.destroy
  redirect '/admin'
end

#フォームの共有(リンク、QR)
get '/share' do
  @form_key = params[:form_key]
  
  form_url = "https://tunebox.onrender.com/form/#{@form_key}"

  qrcode = RQRCode::QRCode.new(form_url)

  png = qrcode.as_png(
    bit_depth: 1,
    border_modules: 4,
    color_mode: ChunkyPNG::COLOR_GRAYSCALE,
    color: 'black',
    file: nil,
    fill: 'white',
    module_px_size: 6,
    size: 200
  )

  @qr_base64 = Base64.strict_encode64(png.to_s)
  
  erb :'admin/share', layout: false
end

#ログイン関連
get '/login_form' do
  @title = "管理者ログイン"
  @notice = session.delete(:notice)
  erb :'admin/login_form', layout: :'admin/layout'
end

get '/signup_form' do
  @title = "新規アカウント作成"
  @notice = session.delete(:notice)
  erb :'admin/signup_form', layout: :'admin/layout'
end

get "/user/edit" do
  @title = "アカウント情報 編集"
  @notice = session.delete(:notice) 
  
  @user = User.find(session[:user_id])
  erb :'admin/user_edit_form', layout: :'admin/layout'
end

get '/user/change_password_form' do
  if session[:user_id].nil?
    redirect '/login_form'
  end
  @notice = session.delete(:notice)
  
  erb :'admin/change_password_form', layout: :'admin/layout'
end

post '/login' do
  user = User.find_by(mail: params[:mail])

  if user && user.authenticate(params[:password])
    session[:user_id] = user.id

    session[:access_token] = user.spotify_access_token
    session[:refresh_token] = user.spotify_refresh_token
    session[:expires_in] = user.spotify_expires_at

    redirect '/admin'
  else
    session[:notice] = "メールアドレスまたはパスワードが間違っています"
    redirect '/login_form'
  end
end

delete '/logout' do
  session.delete(:user_id)
  session.delete(:access_token)
  session.delete(:refresh_token)
  session.delete(:expires_in)
  redirect '/'  
end

patch '/user/edit/:id' do
  @user = User.find(session[:user_id])
  
  @user.first_name = params[:first_name]
  @user.last_name = params[:last_name]
  @user.nick_name = params[:nick_name]
  @user.mail = params[:mail]

  unless params[:password].empty?
    @user.password = params[:password]
  end

  if @user.save
    redirect '/admin' 
  else
    session[:notice] = "更新に失敗しました"
    redirect '/user/edit'
  end
end

patch '/user/change_password' do

  if session[:user_id].nil?
    redirect '/login_form'
  end

  user = User.find(session[:user_id])

  unless BCrypt::Password.new(user.password_digest) == params[:current_password]
    session[:notice] = "現在のパスワードが正しくありません。"
    redirect '/user/change_password_form'
  end

  unless params[:new_password] == params[:confirm_password]
    session[:notice] = "新しいパスワードが一致しません。"
    redirect '/user/change_password_form' 
  end
  
  if BCrypt::Password.new(user.password_digest) == params[:new_password]
    session[:notice] = "前回とは違うパスワードを設定してください。"
    redirect '/user/change_password_form'
  end
  
  user.password = params[:new_password]

  unless user.save
    puts user.errors.full_messages.inspect
    session[:notice] = "パスワードの保存に失敗しました。"
    redirect '/user/change_password_form'
  end
  
  session[:notice] = "パスワードを変更しました。"
  redirect '/user/change_password_form'
end

post '/auth_signup' do
  existing_user = User.find_by(mail: params[:mail])
  if existing_user
    session[:notice] = "このメールアドレスは既に登録されています。"
    redirect '/signup_form'
  end

  session[:signup_params] = {
    first_name: params[:first_name],
    last_name: params[:last_name],
    nick_name: params[:nick_name],
    mail: params[:mail],
    password: params[:password]
  }

  redirect '/signup/spotify_choice'
end

get '/signup/spotify_choice' do
  redirect '/login_form' unless session[:signup_params]  
  erb :'admin/spotify_choice', layout: :'admin/layout'
end

post '/auth/spotify/link/new' do
  redirect '/login_form' unless session[:signup_params]
  redirect '/auth'
end

post '/auth/spotify/link/reconnect' do
  redirect '/login_form' unless session[:user_id]
  
  
  redirect '/auth'
end

get '/signup/skip' do
  unless session[:signup_params]
    redirect '/login_form'
  end

  signup = session.delete(:signup_params)

  user = User.new(
    first_name: signup[:first_name],
    last_name: signup[:last_name],
    nick_name: signup[:nick_name],
    mail: signup[:mail],
    password: signup[:password]
    # Spotify情報は入れない
  )

  if user.save
    session[:user_id] = user.id
    send_signup_confirmation_mail(user)
    redirect '/login_form'
  else
    session[:notice] = user.errors.full_messages.join(', ')
    redirect '/signup_form'
  end
end

def send_signup_confirmation_mail(user)
  Pony.mail(
    to: user.mail,
    from: ENV['MAIL_USER'],
    subject: '【TuneBox】アカウント作成が完了しました',
    body: <<~BODY
      #{user.last_name} #{user.first_name}様

      TuneBoxへのご登録ありがとうございます。
      アカウントの作成が正常に完了しました。

      ■ 登録情報
      ・Spotifyアカウント: #{user.spotify_display_name || "（未連携）"}
      ・メールアドレス: #{user.mail}

      このメールに心当たりがない場合は、
      お手数ですが、このメールに返信をお願いいたします。
      登録内容に問題があると感じた場合は、
      サポートまでご連絡ください。

      今後ともTuneBoxをよろしくお願いいたします。

      TuneBox 開発チーム
    BODY
  )
end

delete '/user_delete' do
  if session[:user_id]
    user = User.find_by(id: session[:user_id])
    if user
      user.forms.destroy_all
      user.destroy
      session.clear  
      redirect '/'  
    else
      status 404
      "ユーザーが見つかりません"
    end
  else
    status 403
    "ログインしていません"
  end
end

# post '/admin/delete_all_users' do
#   User.delete_all
#   Form.delete_all
#   "全ユーザーを削除しました"
# end

#request log
get '/request_log/:form_key' do
  @title = "リクエストログ"
  
  @form = Form.find_by(form_key: params[:form_key])
  
  if session[:user_id].nil?
    redirect '/login_form'
  end
  
  halt(404, "フォームが見つかりません") unless @form
  
  @requests = Request.where(form_key: @form.form_key).order(created_at: :desc)
  
  erb :'admin/request_log', layout: :'admin/layout'
end

delete '/forms/:form_key/tracks/:track_id' do
  form_key = params[:form_key]
  track_id = params[:track_id]

  form = Form.find_by(form_key: form_key)
  halt 404, "フォームが見つかりません" unless form

  playlist_id = form.playlist_id

  form_owner = form.user
  refresh_user_access_token(form_owner) if form_owner.spotify_expires_at && form_owner.spotify_expires_at < Time.now

  token = form_owner.spotify_access_token
  halt 403, "エラー: このフォームの管理者がSpotifyにログインしていません" if token.nil? || token.empty?

  uri = URI("https://api.spotify.com/v1/playlists/#{playlist_id}/tracks")
  request_body = {
    "tracks" => [
      { "uri" => "spotify:track:#{track_id}" }
    ]
  }.to_json

  req = Net::HTTP::Delete.new(uri)
  req['Authorization'] = "Bearer #{token}"
  req['Content-Type'] = 'application/json'
  req.body = request_body

  res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) { |http| http.request(req) }

  if res.is_a?(Net::HTTPSuccess)
    request = Request.find_by(form_key: form_key, track_id: track_id)
    request&.destroy
    redirect "/request_log/#{form_key}"
  else
    halt 500, "Spotify APIエラー: #{res.code} - #{res.body}"
  end
end

#問い合わせ関連
# Pony の共通設定
Pony.options = {
  via: :smtp,
  via_options: {
    address:              'smtp.gmail.com',
    port:                 '587',
    enable_starttls_auto: true,
    user_name:            ENV['MAIL_USER'],
    password:             ENV['MAIL_PASS'],
    authentication:       :plain,
    domain:               "localhost.localdomain"
  }
}

# お問い合わせフォーム表示
get '/contact' do
  @success_message = session.delete(:success_message)
  erb :contact
end

# フォーム送信処理
post '/contact' do
  name         = params[:name]
  contact_type = params[:contact_type]
  user_email   = params[:email]
  message      = params[:message]

  # 利用者宛メール
  Pony.mail(
    to: user_email,
    from: ENV['MAIL_USER'],
    subject: '【TuneBox】お問い合わせありがとうございます',
    body: <<~BODY
      #{name} 様

      お問い合わせありがとうございます。
      以下の内容で受け付けました。

      【氏名】
      #{name}

      【種別】
      #{contact_type}

      【内容】
      #{message}

      TuneBox 開発チーム
    BODY
  )

  # 管理者宛メール
  Pony.mail(
    to: ENV['MAIL_USER'],
    from: ENV['MAIL_USER'],
    subject: '【TuneBox】新しいお問い合わせが届きました',
    body: <<~BODY
      新しいお問い合わせを受け付けました。

      【氏名】
      #{name}

      【種別】
      #{contact_type}

      【送信者メール】
      #{user_email}

      【内容】
      #{message}
    BODY
  )
  
  session[:success_message] = "送信しました"
  redirect '/contact'
end
