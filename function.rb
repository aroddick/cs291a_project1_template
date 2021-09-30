# frozen_string_literal: true

require 'json'
require 'jwt'
require 'pp'

def main(event:, context:)
  # You shouldn't need to use context, but its fields are explained here:
  # https://docs.aws.amazon.com/lambda/latest/dg/ruby-context.html
    headers = event['headers']
    if event['path'] == '/'
        if event['httpMethod'] != 'GET'
            return response(body: event, status: 405)
        elsif !(headers.keys.include?('Authorization') && headers['Authorization'].include?('Bearer '))
            return response(body: event, status: 403)
        end
        token = headers['Authorization'].split('Bearer ')[1] 
        begin
            decodedToken = JWT.decode(token, ENV['JWT_SECRET'])[0]
        rescue => JWT::ExpiredSignature, JWT::ImmatureSignature
            return response(body: event, status: 401)
        rescue => exception
            return response(body: event, status: 403)
        end
        exp = decodedToken['exp']
        nbf = decodedToken['nbf']
        # if Time.now.to_i > exp || Time.now.to_i < nbf
        #     return response(body: event, status: 401)
        # end
        data = decodedToken['data']
        return response(body: data, status: 200)

    elsif event['path'] == '/token'
        if event['httpMethod'] != 'POST'
            return response(body: event, status: 405)
        end
        payload = {
            data: event['body'],
            exp: Time.now.to_i + 5,
            nbf: Time.now.to_i + 2
        }
        token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
        body = {'token' => token}
        response(body: body, status: 201)
    else
        response(body: event, status: 404)
    end

end

def response(body: nil, status: 200)
  {
    body: body ? body.to_json + "\n" : '',
    statusCode: status
  }
end

if $PROGRAM_NAME == __FILE__
  # If you run this file directly via `ruby function.rb` the following code
  # will execute. You can use the code below to help you test your functions
  # without needing to deploy first.
  ENV['JWT_SECRET'] = 'NOTASECRET'

  # Call /token
  PP.pp main(context: {}, event: {
               'body' => '{"name": "bboe"}',
               'headers' => { 'Content-Type' => 'application/json' },
               'httpMethod' => 'POST',
               'path' => '/token'
             })

  # Generate a token
  payload = {
    data: { user_id: 128 },
    exp: Time.now.to_i + 1,
    nbf: Time.now.to_i
  }
  token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
  # Call /
  PP.pp main(context: {}, event: {
               'headers' => { 'Authorization' => "Bearer #{token}",
                              'Content-Type' => 'application/json' },
               'httpMethod' => 'GET',
               'path' => '/'
             })
end
