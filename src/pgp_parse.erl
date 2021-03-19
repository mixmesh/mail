-module(pgp_parse).
-export([decode_stream/2, decode_stream/1, decode_public_key/1,
         decode_signature_packet/1]).
-export([key_id/1, encode_key/1, c14n_key/1]).

-include_lib("apptools/include/log.hrl").
-include("OpenSSL.hrl").

%% Section references can be found in
%% https://tools.ietf.org/pdf/draft-ietf-openpgp-rfc4880bis-10.pdf

-define(PGP_VERSION_4, 4).

%% Section 4.2: Packets Headers
-define(OLD_PACKET_FORMAT, 2#10).
-define(NEW_PACKET_FORMAT, 2#11).

%% Section 4.3: Packets Tags
-define(SIGNATURE_PACKET, 2).
-define(PUBLIC_KEY_PACKET, 6).
-define(USER_ID_PACKET, 13).
-define(PUBLIC_SUBKEY_PACKET, 14).
-define(USER_ATTRIBUTE_PACKET, 17).

%% Section 5.2.3.1: Signature Subpacket Specification
-define(SIGNATURE_CREATION_TIME_SUBPACKET, 2).
-define(SIGNATURE_EXPIRATION_TIME_SUBPACKET, 3).
-define(KEY_EXPIRATION_SUBPACKET, 9).
-define(ISSUER_SUBPACKET, 16).
-define(POLICY_URI_SUBPACKET, 26).

%% Section 9.5: Hash Algorithms
-define(HASH_ALGORITHM_MD5, 1).
-define(HASH_ALGORITHM_SHA1, 2).
-define(HASH_ALGORITHM_RIPEMD160, 3).
-define(HASH_ALGORITHM_SHA256, 8).
-define(HASH_ALGORITHM_SHA384, 9).
-define(HASH_ALGORITHM_SHA512, 10).
-define(HASH_ALGORITHM_SHA224, 11).

%% Section 9.1: Public-Key Algorithms
-define(PUBLIC_KEY_ALGORITHM_RSA_ENCRYPT_OR_SIGN, 1).
-define(PUBLIC_KEY_ALGORITHM_RSA_ENCRYPT, 2).
-define(PUBLIC_KEY_ALGORITHM_RSA_SIGN, 3).
-define(PUBLIC_KEY_ALGORITHM_ELGAMAL, 16).
-define(PUBLIC_KEY_ALGORITHM_DSA, 17).

-type c14n_key() :: binary().
-type key() :: elgamal | {dss, [binary()]} | {rsa, [binary()]}.
-type packet_type() :: signature | primary_key | subkey | user_id.
-type user_id() :: binary().
-type user_attribute() :: binary().

-record(decoder_ctx,
        {primary_key :: {c14n_key(), key()} | undefined,
         subkey :: {c14n_key(), key()} | undefined,
         user_id :: user_id() | undefined,
         user_attribute :: user_attribute() | undefined,
         issuer :: binary()  | undefined,
         handler :: fun((packet_type(), list(), any()) -> any()),
         handler_state :: any(),
         signature_creation_time :: integer() | undefined,
         signature_expiration_time :: integer() | undefined,
         key_expiration :: integer() | undefined, 
         policy_uri :: binary() | undefined,
         skip_signature_check = false :: boolean(),
         critical_subpacket = false :: boolean()}).

%% Exported: decode_stream

decode_stream(Data) ->
    decode_stream(Data, []).
decode_stream(Data, Options) ->
    Packets =
        case proplists:get_bool(file, Options) of
            true ->
                {ok, FileData} = file:read_file(Data),
                FileData;
            false ->
                Data
        end,
    DecodedPackets =
        case proplists:get_bool(armor, Options) of
            true ->
                pgp_armor:decode(Packets);
            false ->
                Packets
        end,
    Handler =
        proplists:get_value(
          handler, Options,
          fun(PacketType, HandlerParams, HandlerState) ->
                  ?dbg_log({default_handler, PacketType, HandlerParams,
                            HandlerState}),
                  HandlerState
          end),
    HandlerState = proplists:get_value(handler_state, Options),
    decode_packets(DecodedPackets, #decoder_ctx{handler = Handler,
                                                handler_state = HandlerState}).

%% Exported: decode_public_key

decode_public_key(<<?PGP_VERSION_4, Timestamp:32, Algorithm,
                    KeyRest/binary>>) ->
    Key = decode_public_key_algorithm(Algorithm, KeyRest),
    {Timestamp, Key}.

decode_public_key_algorithm(?PUBLIC_KEY_ALGORITHM_ELGAMAL, _) ->
    elgamal;
decode_public_key_algorithm(?PUBLIC_KEY_ALGORITHM_DSA, Data) ->
    {dss, read_mpi(Data, 4)};
decode_public_key_algorithm(RSA, Data)
  when RSA == ?PUBLIC_KEY_ALGORITHM_RSA_ENCRYPT_OR_SIGN orelse
       RSA == ?PUBLIC_KEY_ALGORITHM_RSA_ENCRYPT orelse
       RSA == ?PUBLIC_KEY_ALGORITHM_RSA_SIGN ->
    {rsa, lists:reverse(read_mpi(Data, 2))}.

read_mpi(Data) ->
    [Value] = read_mpi(Data, 1),
    Value.
read_mpi(Data, Count) ->
    read_mpi(Data, Count, []).
read_mpi(<<>>, 0, Acc) ->
    lists:reverse(Acc);
read_mpi(<<Length:16, Rest/binary>>, Count, Acc) ->
    ByteLen = (Length + 7) div 8,
    <<Data:ByteLen/binary, Trailer/binary>> = Rest,
    read_mpi(Trailer, Count - 1, [Data | Acc]).

%% Exported: decode_signature_packet

decode_signature_packet(Packet) ->
    Context =
        decode_packet(?SIGNATURE_PACKET, Packet,
                      #decoder_ctx{
                         handler = fun dsp_handler/3,
                         handler_state = [],
                         skip_signature_check = true}),
    Context#decoder_ctx.handler_state.

dsp_handler(signature, [_|Params], []) ->
    Params;
dsp_handler(_, _, State) ->
    State.

%% Exported: key_id

key_id(KeyData) ->
    crypto:hash(sha, KeyData).

%% Exported: encode_key

encode_key(KeyData) ->
    encode_key(KeyData, ?PUBLIC_KEY_PACKET).
encode_key(KeyData, KeyTag) ->
    Id = key_id(c14n_key(KeyData)),
    PK = encode_packet(KeyTag, KeyData),
    Signatures =
        << <<(encode_packet(?USER_ID_PACKET, UserId))/binary,
             (encode_signatures(US))/binary>> ||
            {UserId, US} <- pgp_keystore:get_signatures(Id) >>,
    Subkeys = << <<(encode_key(SK, ?PUBLIC_SUBKEY_PACKET))/binary>> ||
                  SK <- pgp_keystore:get_subkeys(Id) >>,
    <<PK/binary, Signatures/binary, Subkeys/binary>>.

%% Exported: c14n_key

c14n_key(KeyData) ->
    <<16#99, (byte_size(KeyData)):16, KeyData/binary>>.

%%
%% Encode signature
%%

encode_signatures(Signatures) ->
    << <<(encode_packet(?SIGNATURE_PACKET, S))/binary>> || S <- Signatures >>.

%%
%% Encode packet
%%

encode_packet(_, undefined) ->
    <<>>;
encode_packet(Tag, Body) ->
    {LenBits, Length} = case byte_size(Body) of
                            S when S < 16#100 ->
                                {0, <<S>>};
                            M when M < 16#10000 ->
                                {1, <<M:16>>};
                            L when L < 16#100000000 ->
                                {2, <<L:32>>}
                        end,
    <<?OLD_PACKET_FORMAT:2, Tag:4, LenBits:2, Length/binary, Body/binary>>.

%%
%% Decode packets
%%

%% Section 4.2.1: Old Format Packet Lengths
decode_packets(<<?OLD_PACKET_FORMAT:2, Tag:4, LengthType:2, Packets/binary>>,
               Context) ->
    LengthSize = old_packet_length_size(LengthType),
    <<Length:LengthSize, Packet:Length/binary, RemainingPackets/binary>> =
        Packets,
    NewContext = decode_packet(Tag, Packet, Context),
    decode_packets(RemainingPackets, NewContext);
%% Section 4.2.2: New Format Packet Lengths
decode_packets(<<?NEW_PACKET_FORMAT:2, Tag:6, Rest/binary>>, Context) ->
    {Packet, RemainingPackets} =  decode_new_packet(Rest),
    NewContext = decode_packet(Tag, Packet, Context),
    decode_packets(RemainingPackets, NewContext).

old_packet_length_size(0) -> 8; % One octet packet length
old_packet_length_size(1) -> 16; % Two octets packet length
old_packet_length_size(2) -> 32. % Four octets packet length

decode_new_packet(<<Length, Packet:Length/binary, RemainingPackets/binary>>)
  when Length =< 191 ->
    %% One octet packet length
    {Packet, RemainingPackets};
decode_new_packet(<<FirstOctet, SecondOctet, Rest/binary>>)
  when FirstOctet >= 192 andalso FirstOctet =< 223 ->
    Length = (FirstOctet - 192) bsl 8 + SecondOctet + 192,
    <<Packet:Length/binary, RemainingPackets/binary>> = Rest,
    %% Two octet packet length
    {Packet, RemainingPackets};

decode_new_packet(<<255, Length:32, Packet:Length/binary,
                    RemainingPackets/binary>>) ->
    %% Five octet packet length
    {Packet, RemainingPackets}.

%% Section 5.2: Signature Packet (Tag 2)
decode_packet(?SIGNATURE_PACKET,
              <<?PGP_VERSION_4,
                SignatureType,
                PublicKeyAlgorithm,
                HashAlgorithm,
                HashedSubpacketsLength:16,
                HashedSubpackets:HashedSubpacketsLength/binary,
                UnhashedSubpacketsLength:16,
                UnhashedSubpackets:UnhashedSubpacketsLength/binary,
                SignedHashLeft16:2/binary,
                Signature/binary>> = SignatureData,
              Context) ->
    Expected =
        case Context#decoder_ctx.skip_signature_check of
            true ->
                <<SignedHashLeft16:2/binary>>;
            false ->
                hash_signature_packet(
                  SignatureType, PublicKeyAlgorithm, HashAlgorithm,
                  HashedSubpackets, Context)
        end,
    <<SignedHashLeft16:2/binary, _/binary>> = Expected,
    ContextAfterHashedSubpackets =
        decode_signed_subpackets(HashedSubpackets, Context),
    ContextAfterUnhashedSubpackets =
        decode_signed_subpackets(UnhashedSubpackets,
                                 ContextAfterHashedSubpackets),
    verify_signature_packet(
      PublicKeyAlgorithm, HashAlgorithm, Expected, Signature, SignatureType,
      ContextAfterUnhashedSubpackets),
    Handler = ContextAfterUnhashedSubpackets#decoder_ctx.handler,
    SignatureLevel = signature_type_to_signature_level(SignatureType),
    HandlerState =
        Handler(
          signature,
          [SignatureData,
           ContextAfterHashedSubpackets#decoder_ctx.signature_expiration_time,
           ContextAfterHashedSubpackets#decoder_ctx.signature_creation_time,
           ContextAfterHashedSubpackets#decoder_ctx.policy_uri,
           ContextAfterUnhashedSubpackets#decoder_ctx.issuer,
           ContextAfterHashedSubpackets#decoder_ctx.key_expiration,
           SignatureLevel],
          ContextAfterUnhashedSubpackets#decoder_ctx.handler_state),
    ContextAfterUnhashedSubpackets#decoder_ctx{handler_state = HandlerState};
%% Section 5.5.1.1: Public-Key Packet (Tag 6)
%% Section 5.5.1.2: Public-Subkey Packet (Tag 14)
decode_packet(Tag, KeyData, Context)
  when Tag == ?PUBLIC_KEY_PACKET orelse Tag == ?PUBLIC_SUBKEY_PACKET ->
    {Timestamp, Key} = decode_public_key(KeyData),
    Handler = Context#decoder_ctx.handler,
    CombinedKey = {c14n_key(KeyData), Key},
    case Tag of
        ?PUBLIC_KEY_PACKET ->
            HandlerState =
                Handler(primary_key,
                        [CombinedKey, KeyData, Timestamp],
                        Context#decoder_ctx.handler_state),
            Context#decoder_ctx{
              primary_key = CombinedKey,
              handler_state = HandlerState,
              user_id = undefined};
        ?PUBLIC_SUBKEY_PACKET ->
            HandlerState =
                Handler(subkey,
                        [CombinedKey,
                         KeyData,
                         Timestamp,
                         Context#decoder_ctx.primary_key],
                        Context#decoder_ctx.handler_state),
            Context#decoder_ctx{subkey = CombinedKey,
                                handler_state = HandlerState,
                                user_id = undefined}
    end;
%% Section 5.13: User Attribute Packet (Tag 17)
decode_packet(?USER_ATTRIBUTE_PACKET, UserAttribute, C) ->
    C#decoder_ctx{
      user_attribute =
          <<16#D1, (byte_size(UserAttribute)):32, UserAttribute/binary>>};
%% Section 5.12: User ID Packet (Tag 13)
decode_packet(?USER_ID_PACKET, UserId, Context) ->
    Handler = Context#decoder_ctx.handler,
    HandlerState = Handler(user_id, [UserId], Context#decoder_ctx.handler_state),
    Context#decoder_ctx{
      user_id = <<16#B4, (byte_size(UserId)):32, UserId/binary>>,
      handler_state = HandlerState,
      user_attribute = undefined}.

%%
%% Signature packet handling
%%

hash_signature_packet(SignatureType, PublicKeyAlgorithm, HashAlgorithm,
                      HashedSubpackets, Context) ->
    HashState = crypto:hash_init(pgp_to_crypto_digest_type(HashAlgorithm)), 
    FinalHashState =
        case SignatureType of
            %% 0x18: Subkey Binding Signature
            %% 0x19: Primary Key Binding Signature
            KeyBinding when KeyBinding == 16#18 orelse KeyBinding == 16#19 ->
                {PrimaryKey, _} = Context#decoder_ctx.primary_key,
                {Subkey, _} = Context#decoder_ctx.subkey,
                crypto:hash_update(
                  crypto:hash_update(HashState, PrimaryKey), Subkey);
            %% 0x10: Generic certification of a User ID and Public-Key packet
            %% 0x11: Persona certification of a User ID and Public-Key packet
            %% 0x12: Casual certification of a User ID and Public-Key packet
            %% 0x13: Positive certification of a User ID and Public-Key packet
            %% 0x30: Certification revocation signature
            Certification when (Certification >= 16#10 andalso
                                Certification =< 16#13) orelse
                               Certification == 16#30 ->
                {PrimaryKey, _} = Context#decoder_ctx.primary_key,
                UserId =
                    case Context#decoder_ctx.user_attribute of
                        undefined ->
                            Context#decoder_ctx.user_id;
                        UserAttribute ->
                            UserAttribute
                    end,
                crypto:hash_update(
                  crypto:hash_update(HashState, PrimaryKey), UserId);
            _ ->
                ?error_log({unknown_signature_type, SignatureType}),
                HashState
        end,
    FinalData =
        <<?PGP_VERSION_4,
          SignatureType,
          PublicKeyAlgorithm,
          HashAlgorithm,
          (byte_size(HashedSubpackets)):16,
          HashedSubpackets/binary>>,
    Trailer = <<?PGP_VERSION_4, 16#FF, (byte_size(FinalData)):32>>,
    crypto:hash_final(
      crypto:hash_update(
        crypto:hash_update(FinalHashState, FinalData), Trailer)).

pgp_to_crypto_digest_type(?HASH_ALGORITHM_MD5) -> md5;
pgp_to_crypto_digest_type(?HASH_ALGORITHM_SHA1) -> sha;
pgp_to_crypto_digest_type(?HASH_ALGORITHM_RIPEMD160) -> ripemd160;
pgp_to_crypto_digest_type(?HASH_ALGORITHM_SHA256) -> sha256;
pgp_to_crypto_digest_type(?HASH_ALGORITHM_SHA384) -> sha384;
pgp_to_crypto_digest_type(?HASH_ALGORITHM_SHA512) -> sha512;
pgp_to_crypto_digest_type(?HASH_ALGORITHM_SHA224) -> sha224.

decode_signed_subpackets(<<>>, Context) ->
    Context;
decode_signed_subpackets(Packets, Context) ->
    {Payload, Rest} = decode_new_packet(Packets),
    NewContext = decode_signed_subpacket(Payload, Context),
    decode_signed_subpackets(
      Rest, NewContext#decoder_ctx{critical_subpacket = false}).

decode_signed_subpacket(<<?SIGNATURE_CREATION_TIME_SUBPACKET, Timestamp:32>>,
                        Context) ->
    Context#decoder_ctx{signature_creation_time = Timestamp};
decode_signed_subpacket(<<?SIGNATURE_EXPIRATION_TIME_SUBPACKET, Timestamp:32>>,
                        Context) ->
    Context#decoder_ctx{signature_expiration_time = Timestamp};
decode_signed_subpacket(<<?KEY_EXPIRATION_SUBPACKET, Timestamp:32>>, Context) ->
    Context#decoder_ctx{key_expiration = Timestamp};
decode_signed_subpacket(<<?ISSUER_SUBPACKET, Issuer:8/binary>>, Context) ->
    Context#decoder_ctx{issuer = Issuer};
decode_signed_subpacket(<<?POLICY_URI_SUBPACKET, Uri/binary>>, Context) ->
    Context#decoder_ctx{policy_uri = Uri};
decode_signed_subpacket(<<Tag, Rest/binary>>, Context)
  when Tag band 128 == 128 ->
    decode_signed_subpacket(<<(Tag band 127), Rest/binary>>,
                            Context#decoder_ctx{critical_subpacket = true});
decode_signed_subpacket(<<_Tag, _/binary>>,
                        Context = #decoder_ctx{critical_subpacket = false}) ->
    Context.

verify_signature_packet(_, _, _, _, _,
                        #decoder_ctx{skip_signature_check = true}) ->
    ok;
verify_signature_packet(PublicKeyAlgorithm, HashAlgorithm, Hash, Signature,
                        SignatureType, Context) ->
    CryptoDigestType = pgp_to_crypto_digest_type(HashAlgorithm),
    CryptoSignature =
        case PublicKeyAlgorithm of
            _ when PublicKeyAlgorithm ==
                     ?PUBLIC_KEY_ALGORITHM_RSA_ENCRYPT_OR_SIGN orelse
                   PublicKeyAlgorithm == ?PUBLIC_KEY_ALGORITHM_RSA_SIGN ->
                read_mpi(Signature);
            ?PUBLIC_KEY_ALGORITHM_DSA ->
                [R, S] = [binary:decode_unsigned(X, big) ||
                             X <- read_mpi(Signature, 2)],
                {ok, EncodedDssSignature} =
                    'OpenSSL':encode(
                      'DssSignature', #'DssSignature'{r = R, s = S}),
                EncodedDssSignature;
            _ ->
                ?error_log({unknown_crypto_signature, PublicKeyAlgorithm})
        end,
    case SignatureType of
        16#18 ->
            {_, {CryptoAlgorithm, CryptoKey}} = Context#decoder_ctx.primary_key,
            true = crypto:verify(
                     CryptoAlgorithm, CryptoDigestType, {digest, Hash},
                     CryptoSignature, CryptoKey);
        _ when SignatureType >= 16#10 andalso SignatureType =< 16#13 ->
            Issuer = Context#decoder_ctx.issuer,
            {C14NKey, {CryptoAlgorithm, CryptoKey}} =
                Context#decoder_ctx.primary_key,
            case binary:longest_common_suffix(
                   [Issuer, key_id(C14NKey)]) == byte_size(Issuer) of
                true ->
                    true = crypto:verify(
                             CryptoAlgorithm, CryptoDigestType, {digest, Hash},
                             CryptoSignature, CryptoKey);
                false ->
                    ?error_log(nyi)
            end;
        _ ->
            unknown
    end.

signature_type_to_signature_level(SignatureType)
  when SignatureType >= 16#11 andalso SignatureType =< 16#13 ->
    [SignatureType - 16#10 + $0];
signature_type_to_signature_level(_) ->
    " ".
