(setq
   *CONSTRUCTION
   `(mapcar char (chop "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"))
   *IDENTIFIER
   `(mapcar char (chop "WireGuard v1 zx2c4 Jason@zx2c4.com"))
   *LABEL_MAC1
   `(mapcar char (chop "mac1----"))
   *LABEL_COOKIE
   `(mapcar char (chop "cookie--"))
   *DEMO_SERVER "demo.wireguard.com"
   *DEMO_PORT   "12913"
   *PF_INET    2
   *SOCK_DGRAM 2
   *PING_LABEL
   `(mapcar char (chop "WireGuard"))
   # full ip-icmp packet, stolen
   *PING_DATA
      (69 0 0 37 0 0 0 0 20 1 143 91 10 189 129 2 10 189 129 1 8 0
         27 250 3 153 1 182 87 105 114 101 71 117 97 114 100 0 0 0 
         0 0 0 0 0 0 0 0 ) )
(def 'prv car)
(def 'pub cadr)
(de dh_generate NIL # already seeded
   (make (do 32 (link (rand 0 255)))) )
(de ephemrl-pair NIL # (Priv Pub)
   (make (link (dh_generate) (dh_pubkey (car (made))))) )
(de hmac (Key Msg) # blake2s
   (let Key (copy Key)
      (and
         (> (length Key) 64)
         (setq Key (blake2s Key)) ) 
      (setq Key (need -64 Key 0))
      (blake2s
         (conc
            (mapcar x| (need 64 `(hex "5C")) Key)
            (blake2s (conc (mapcar x| (need 64 `(hex "36")) Key) Msg)) ) ) ) )
(de hash32 (Msg)
   (blake2s Msg) )
(de mac (Key Msg)
   (blake2s Msg Key 16) )
(de kdf1 (C D)
   (hmac (hmac C D) (cons 1)) )
(de kdf2 (C D)
   (let Z (hmac C D)
      (list
         (setq @ (hmac Z (cons 1)))
         (hmac Z (append @ (cons 2))) ) ) ) 
(de kdf3 (C D)
   (let Z (hmac C D)
      (list
         (setq @ (hmac Z (cons 1)))
         (setq @ (hmac Z (append @ (cons 2))))
         (hmac Z (append @ (cons 3))) ) ) ) 
(de dh_pubkey (S)
   (use P
      (native
         "libmonocypher.so.2"
         "crypto_x25519_public_key"
         NIL
         '(P (32 B . 32))
         (cons NIL (32) S) )
      P ) )
(de dh (S P)
   (use R
      (native
         "libmonocypher.so.2"
         "crypto_x25519"
         'I
         '(R (32 B . 32))
         (cons NIL (32) S)
         (cons NIL (32) P) )
      R ) ) 
(de lock_aead (K N P A)
   (let 
      (AL (length A)
         PL (length P)
         Mac NIL
         CH NIL )
      (native
         "libmonocypher.so.2"
         "crypto_lock_aead"
         NIL
         '(Mac (16 B . 16))
         (if P  # for empty plain data
            (list 'CH (cons PL 'B PL)) 
            0 )
         (cons NIL (32) K)
         (cons NIL (12) N)
         (cons NIL (cons AL) A)
         AL
         (cons NIL (cons PL) P)
         PL )
      (conc CH Mac) ) )
# TODO: check return value, now assume always success
(de unlock_aead (K N C A)
   (let
      (AL (length A)
         CL (- (length C) 16)
         P NIL)
      (native
         "libmonocypher.so.2"
         "crypto_unlock_aead"
         'I
         (if (=0 CL)  # for empty crypted 
            @ 
            (list 'P (cons CL 'B CL)) )
         (cons NIL (32) K)
         (cons NIL (12) N)
         (cons NIL (16) (tail 16 C))
         (cons NIL (cons AL) A)
         AL
         (cons NIL (cons CL) (head CL C))
         CL )
      P ) )
(de tai64n NIL
   (let
      (S 
         (+
            4611686018427387914
            (-
               (+ (* 86400 (date T)) (time T))
               (* 86400 (date 1970 1 1)) ) )
         N (in '(date "+%N") (read)) ) # for real
      (conc (big64 S) (big32 N)) ) )
(de nonce (N)
   (conc (need 4 0) (little64 N)) )
(de little32 (N)
   (make
      (do 4
         (link (& N 255))
         (setq N (>> 8 N)) ) ) )
(de little64 (N)
   (make
      (do 8
         (link (& N 255))
         (setq N (>> 8 N)) ) ) )
(de big32 (N)
   (make
      (do 4
         (yoke (& N 255))
         (setq N (>> 8 N)) ) ) )
(de big64 (N)
   (make
      (do 8
         (yoke (& N 255))
         (setq N (>> 8 N)) ) ) )
(de socket NIL
   (native 
      "@" 
      "socket" 
      'I 
      *PF_INET 
      *SOCK_DGRAM 
      17 # IPPROTO_UDP
   ) )
(de getaddrinfo (Host Port)
   (let (Hints NIL  Res NIL)
      (setq Hints (native "@" "calloc" 'N 1 48))
      (struct Hints 'I (0 . 4) -2 -2) # 0, PF_INET, SOCK_DGRAM
      (native "@" "getaddrinfo" NIL Host Port Hints '(Res (8 . N) . 0))
      (native "@" "free" NIL Hints)
      (struct
         Res 
         '(I I I I I I N N N) ) ) )
(de server (Host Port)
   (let R (getaddrinfo Host Port)
      (list 
         (socket)
         (get R 7) # ai_addr
         (get R 5) # ai_addrlen
      ) ) )
(de sendto (S B) # without return check
   (let BL (length B)
      (native
         "@"
         "sendto"
         NIL
         (car S)
         (cons NIL (cons BL) B)
         BL
         0
         (cadr S)
         (caddr S) ) ) )  
(de recvfrom (S) # without return check
   (let
      (Buf NIL
         N
         (native
            "@"
            "recvfrom"
            'N
            (car S)
            '(Buf (1024 B . 1024))
            1024
            0
            0
            0 ) )
      (head N Buf) ) )
(de start-handshake NIL
   (make
      (link 1 0 0 0)
      (chain (little32 28))
      (chain (pub *E))
      (setq 
         *C (kdf1 *C (pub *E))
         *H (hash32 (append *H (pub *E))) 
         @  (kdf2 *C (dh (prv *E) *RPub))
         *C (car @)
         *K (cadr @) )
      (chain (setq @ (lock_aead *K (nonce 0) *Pub *H)))
      (setq 
         *H (hash32 (append *H @))
         # starting for tai64n
         @  (kdf2 *C (dh *Prv *RPub))
         *C (car @)
         *K (cadr @) )
      (chain
         (setq @ (lock_aead *K (nonce 0) (tai64n) *H)) )
      (setq *H (hash32 (append *H @)))
      # mac1 and mac2
      (chain (mac (hash32 (append *LABEL_MAC1 *RPub)) (made)))
      (chain (need 16 0)) ) )
# full packet
(de fin-handshake (Lst)
   (let
      (Er (head 32 (nth Lst 13))
         Crypted (head 16 (nth Lst 45)) 
         Mac1 (head 16 (nth Lst 61))
         Empty T )
      (test (2 0 0 0) (head 4 Lst))
      # check our index in first byte
      (test 28 (get Lst 9))
      # check MAC1
      (test
         Mac1
         (mac (hash32 (append *LABEL_MAC1 *Pub)) (head 60 Lst)) )
      (setq
         *IndexR (head 4 (nth Lst 5))
         *C (kdf1 *C Er)
         *H (hash32 (append *H Er))
         *C (kdf1 *C (dh (prv *E) Er))
         *C (kdf1 *C (dh *Prv Er))
         @  (kdf3 *C *Pre)
         *C (car @)
         *K (caddr @)
         *H (hash32 (append *H (cadr @)))
         Empty (unlock_aead *K (nonce 0) Crypted *H)
         *H (hash32 (append *H Crypted)) )
      (test NIL Empty)  # receive empty payload
      (setq             # split keys
         @ (kdf2 *C)
         *Enc (car @)
         *Dec (cadr @) ) ) )
(de encryption (D)
   (make
      (link 4 0 0 0)
      (chain 
         (copy *IndexR)
         (little64 *Nsend)
         (lock_aead 
            *Enc
            (nonce (swap '*Nsend (+ 1 *Nsend)))
            D 
            NIL ) ) ) ) 
(de decryption (Lst) # full packet
   # header and index's first byte
   (test (4 0 0 0 28) (head 5 Lst))
   # extra check for synced counter
   (test (head 8 (nth Lst 9)) (little64 *Nrecv))
   (unlock_aead 
      *Dec 
      (nonce (swap '*Nrecv (+ 1 *Nrecv)))
      (nth Lst 17)
      NIL ) )

