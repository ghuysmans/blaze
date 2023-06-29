open Srv
open Rresult

let run : Unix.file_descr -> ('a, 'err) Colombe.State.t -> ('a, 'err) result =
 fun flow state ->
  let rec go = function
    | Colombe.State.Read { buffer; off; len; k } -> (
        match Unix.read flow buffer off len with
        | 0 -> (go <.> k) `End
        | len -> (go <.> k) (`Len len))
    | Colombe.State.Write { buffer; off; len; k } ->
        let len = Unix.write flow (Bytes.unsafe_of_string buffer) off len in
        (go <.> k) len
    | Colombe.State.Return v -> Ok v
    | Colombe.State.Error err -> Error err in
  go state

let serve with_metadata kind sockaddr domain output =
  let socket =
    Unix.socket (Unix.domain_of_sockaddr sockaddr) Unix.SOCK_STREAM 0 in
  Unix.setsockopt socket SO_REUSEADDR true ;
  Unix.setsockopt socket SO_REUSEPORT true ;
  let lift = function
    | Ok v -> Ok v
    | Error (`Protocol (`Protocol err)) -> Error (`Protocol err)
    | Error (`Protocol (#tls_error as tls_error)) -> Error (`Tls tls_error)
    | Error (`Tls (`Protocol err)) -> Error (`Protocol err)
    | Error (`Tls (#tls_error as tls_error)) -> Error (`Tls tls_error)
    | Error (`Application err) -> Error (`Application err) in
  let rec go socket =
    let flow, peer = Unix.accept socket in
    let res =
      match kind with
      | `Clear ->
        Colombe.State.Context.make () |>
        handle ~sockaddr ~domain |>
        run flow
      | `Tls tls ->
        Sendmail_with_starttls.Context_with_tls.make () |>
        handle_with_starttls ~tls ~sockaddr ~domain |>
        run flow |>
        lift
    in
    match res with
    | Ok `Quit ->
        Unix.close flow ;
        go socket
    | Ok (`Mail (domain_from, from, recipients, mail)) ->
        show ~with_metadata ~domain_from ~from ~recipients mail output ;
        Unix.close flow ;
        Unix.close socket ;
        `Ok ()
    | Error err ->
        Fmt.epr "[%a][%a]: %a.\n%!"
          Fmt.(styled `Red string)
          "ERROR"
          Fmt.(styled `Cyan pp_sockaddr)
          peer pp_error err ;
        Unix.close flow ;
        go socket in
  try
    Unix.bind socket sockaddr ;
    Unix.listen socket 1 ;
    go socket
  with Unix.Unix_error (err, f, arg) ->
    `Error (false, Fmt.str "%s(%s): %s." f arg (Unix.error_message err))

let run _ local nameservers timeout with_metadata private_key certificate
    bind_name domain output =
  let dns = Ldns.create ?nameservers ~timeout ~local () in
  match sockaddr_of_bind_name dns bind_name with
  | Error (`Msg err) -> `Error (false, Fmt.str "%s." err)
  | Ok sockaddr ->
  match (private_key, certificate) with
  | None, None -> serve with_metadata `Clear sockaddr domain output
  | Some private_key, Some certificate -> (
      match
        (private_key_of_file private_key, certificate_of_file certificate)
      with
      | Ok private_key, Ok certificate ->
          let tls =
            Tls.Config.server
              ~certificates:(`Single ([ certificate ], private_key))
              () in
          serve with_metadata (`Tls tls) sockaddr domain output
      | Error (`Msg err), _ -> `Error (false, Fmt.str "%s." err)
      | _, Error (`Msg err) -> `Error (false, Fmt.str "%s." err))
  | Some _, None | None, Some _ ->
      `Error (true, "Missing elements to initiate a STARTTLS server.")

open Cmdliner
open Args

let bind_name =
  let parser str =
    match Fpath.of_string str with
    | Ok v when Sys.file_exists str -> Ok (`Unix v)
    | _ ->
    match String.split_on_char ':' str with
    | [ addr; port ] -> (
        match
          ( Ipaddr.of_string addr,
            Domain_name.(of_string addr >>= host),
            int_of_string port )
        with
        | Ok inet_addr, _, port -> Ok (`Inet_addr (inet_addr, port))
        | _, Ok host, port -> Ok (`Host (host, port))
        | _ -> R.error_msgf "Invalid bind address: %S" str
        | exception _ -> R.error_msgf "Invalid bind address: %S" str)
    | [ addr ] -> (
        match
          (Ipaddr.of_string addr, Domain_name.(of_string addr >>= host))
        with
        | Ok inet_addr, _ -> Ok (`Inet_addr (inet_addr, 25))
        | _, Ok host -> Ok (`Host (host, 25))
        | _ -> R.error_msgf "Invalid bind address: %S" str)
    | _ -> R.error_msgf "Invalid bind address: %S" str in
  let pp ppf = function
    | `Inet_addr (inet_addr, 25) -> Fmt.pf ppf "%a" Ipaddr.pp inet_addr
    | `Inet_addr (inet_addr, port) ->
        Fmt.pf ppf "%a:%d" Ipaddr.pp inet_addr port
    | `Host (host, 25) -> Domain_name.pp ppf host
    | `Host (host, port) -> Fmt.pf ppf "%a:%d" Domain_name.pp host port
    | `Unix path -> Fpath.pp ppf path in
  Arg.conv (parser, pp)

let default_bind_name = `Inet_addr (Ipaddr.V4 Ipaddr.V4.any, 25)

let bind_name =
  let doc = "The address where the server listens." in
  Arg.(
    value & pos 0 bind_name default_bind_name & info [] ~docv:"<address>" ~doc)

let new_file = Arg.conv (Fpath.of_string, Fpath.pp)

let output =
  let doc = "The path of the received email." in
  Arg.(value & opt (some new_file) None & info [ "o"; "output" ] ~doc)

let default_domain = R.get_ok (Domain_name.of_string (Unix.gethostname ()))
let domain = Arg.conv (Domain_name.of_string, Domain_name.pp)

let domain =
  let doc = "Hostname of the machine." in
  Arg.(value & opt domain default_domain & info [ "h"; "hostname" ] ~doc)

let existing_file =
  let parser str =
    match Fpath.of_string str with
    | Ok _ as v when Sys.file_exists str -> v
    | Ok v -> R.error_msgf "%a does not exist" Fpath.pp v
    | Error _ as err -> err in
  Arg.conv (parser, Fpath.pp)

let private_key =
  let doc = "Private key to initiate the STARTTLS extension." in
  Arg.(value & opt (some existing_file) None & info [ "k"; "key" ] ~doc)

let certificate =
  let doc = "Certificate to initiate the STARTTLS extension." in
  Arg.(value & opt (some existing_file) None & info [ "c"; "certificate" ] ~doc)

let with_metadata =
  let doc =
    "Show $(i,meta-data) recorded by the server. If this option is not used \
     with $(b,-o), the output will use the NEWLINE convention instead to print \
     out the incoming email instead of CRLF." in
  Arg.(value & flag & info [ "with-data" ] ~doc)

let cmd =
  let doc = "Initiate a SMTP server to receive $(b,one) email." in
  let man =
    [
      `S Manpage.s_description;
      `P "$(tname) launches a SMTP server to receive an email.";
    ] in
  Cmd.v (Cmd.info "srv" ~doc ~man)
    Term.(
      ret
        (const run
        $ setup_logs
        $ setup_local_dns
        $ nameserver
        $ timeout
        $ with_metadata
        $ private_key
        $ certificate
        $ bind_name
        $ domain
        $ output))

let () = Cmd.(exit @@ eval cmd)
