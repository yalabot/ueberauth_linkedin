defmodule Ueberauth.Strategy.LinkedIn do
  @moduledoc """
  LinkedIn Strategy for Überauth.
  """

  use Ueberauth.Strategy,
    uid_field: :id,
    default_scope: "r_liteprofile r_emailaddress",
    profile_image_size: 400

  alias Ueberauth.Auth.Info
  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra

  @state_cookie_name "ueberauth_linkedin_state"

  @doc """
  Handles initial request for LinkedIn authentication.
  """
  def handle_request!(conn) do
    scopes = conn.params["scope"] || option(conn, :default_scope)
    state =
      conn.params["state"] || Base.encode64(:crypto.strong_rand_bytes(16))

    opts = [scope: scopes,
            state: state,
            redirect_uri: callback_url(conn)]

    conn
    |> put_resp_cookie(@state_cookie_name, state)
    |> redirect!(Ueberauth.Strategy.LinkedIn.OAuth.authorize_url!(opts))
  end

  @doc """
  Handles the callback from LinkedIn.
  """
  def handle_callback!(%Plug.Conn{params: %{"code" => code,
                                            "state" => state}} = conn) do
    opts = [redirect_uri: callback_url(conn)]
    %OAuth2.Client{token: token} = Ueberauth.Strategy.LinkedIn.OAuth.get_token!([code: code], opts)

    if token.access_token == nil do
      token_error = token.other_params["error"]
      token_error_description = token.other_params["error_description"]
      conn
      |> delete_resp_cookie(@state_cookie_name)
      |> set_errors!([error(token_error, token_error_description)])
    else
      if conn.cookies[@state_cookie_name] == state do
        conn
        |> delete_resp_cookie(@state_cookie_name)
        |> fetch_user(token)
        |> fetch_email(token)
      else
        conn
        |> delete_resp_cookie(@state_cookie_name)
        |> set_errors!([error("csrf", "CSRF token mismatch")])
      end
    end
  end

  @doc false
  def handle_callback!(conn) do
    conn
    |> delete_resp_cookie(@state_cookie_name)
    |> set_errors!([error("missing_code", "No code received")])
  end

  @doc false
  def handle_cleanup!(conn) do
    conn
    |> put_private(:linkedin_user, nil)
    |> put_private(:linkedin_email, nil)
    |> put_private(:linkedin_token, nil)
  end

  @doc """
  Fetches the uid field from the response.
  """
  def uid(conn) do
    uid_field =
      conn
      |> option(:uid_field)
      |> to_string

    conn.private.linkedin_user[uid_field]
  end

  @doc """
  Includes the credentials from the linkedin response.
  """
  def credentials(conn) do
    token = conn.private.linkedin_token

    %Credentials{
      expires: !!token.expires_at,
      expires_at: token.expires_at,
      refresh_token: token.refresh_token,
      token: token.access_token
    }
  end

  @doc """
  Fetches the fields to populate the info section of `Ueberauth.Auth` struct.
  """
  def info(conn) do
    raw_user_response = conn.private.linkedin_user
    first_name = get_user_field(raw_user_response, "firstName")
    last_name = get_user_field(raw_user_response, "lastName")
    email = conn.private[:linkedin_email]
    profile_image_size = option(conn, :profile_image_size)

    %Info{
      first_name: first_name,
      last_name: last_name,
      name: first_name <> " " <> last_name,
      image: get_user_image_url(raw_user_response, profile_image_size),
      email: email
    }
  end

  @doc """
  Stores the raw information (including the token) obtained from
  the linkedin callback.
  """
  def extra(conn) do
    %Extra{
      raw_info: %{
        token: conn.private.linkedin_token,
        user: conn.private.linkedin_user
      }
    }
  end

  defp skip_url_encode_option, do: [path_encode_fun: fn(a) -> a end]

  defp user_query do
    "/v2/me?projection=(id,firstName,lastName,profilePicture(displayImage~:playableStreams))"
  end

  defp email_query do
    "/v2/emailAddress?q=members&projection=(elements*(handle~))"
  end

  defp fetch_user(conn, token) do
    conn = put_private(conn, :linkedin_token, token)
    resp = Ueberauth.Strategy.LinkedIn.OAuth.get(token, user_query, [], skip_url_encode_option)

    case resp do
      { :ok, %OAuth2.Response{status_code: status, body: _body}} when status in [401, 403] ->
        set_errors!(conn, [error("token", "unauthorized")])
      { :ok, %OAuth2.Response{status_code: status_code, body: user} }
        when status_code in 200..399 ->
          put_private(conn, :linkedin_user, user)
      { :error, %OAuth2.Error{reason: reason} } ->
        set_errors!(conn, [error("OAuth2", reason)])
    end
  end

  defp fetch_email(conn, token) do
    resp = Ueberauth.Strategy.LinkedIn.OAuth.get(token, email_query, [], skip_url_encode_option)

    case resp do
      { :ok, %OAuth2.Response{status_code: status, body: _body}} when status in [401, 403] ->
        conn
      { :ok, %OAuth2.Response{status_code: status_code, body: email_response} }
        when status_code in 200..399 ->
          with %{"elements" => [email_element | _]} <- email_response,
              email when is_binary(email) <- get_in(email_element, ["handle~", "emailAddress"]) do
            put_private(conn, :linkedin_email, email)
          else
            _ ->
              conn
          end
      { :error, %OAuth2.Error{reason: reason} } ->
        set_errors!(conn, [error("OAuth2", reason)])
    end
  end

  defp option(conn, key) do
    Dict.get(options(conn), key, Dict.get(default_options, key))
  end

  defp get_user_image_url(raw_user_response, profile_image_size) do
    with profile_images when is_list(profile_images) <- get_in(raw_user_response, ["profilePicture", "displayImage~", "elements"]) do
      Enum.find_value profile_images, fn %{"data" => data, "identifiers" => identifiers} ->
        if get_in(data, ["com.linkedin.digitalmedia.mediaartifact.StillImage", "storageSize", "width"]) == profile_image_size do
          Enum.at(identifiers, 0)
          |> Map.get("identifier")
        end
      end
    end
  end

  defp get_user_field(raw_user_response, field_name) do
    with field when is_map(field) <- raw_user_response[field_name],
         %{"country" => country, "language" => language} <- field["preferredLocale"] do
      locale_id = language <> "_" <> country
      get_in(field, ["localized", locale_id])
    end
  end
end
