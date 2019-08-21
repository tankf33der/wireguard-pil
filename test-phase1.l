`(== 64 64)
(seed (in "/dev/urandom" (rd 8)))
(load "blake2s.l")
(load "functions.l")

# wg genkey | tee privatekey | wg pubkey > publickey
# for both peers
(setq
   *Pubi (154 108 43 117 98 96 69 36 205 12 89 138 107 175 219 237 218 223 2 25 78 197 229 42 161 22 45 60 130 106 169 102)
   *Privi (232 43 9 6 248 75 27 169 97 126 88 32 208 140 114 173 95 149 255 62 139 2 8 127 54 255 130 168 40 84 17 72)
   *Pubr (214 143 204 172 63 57 112 125 125 190 140 169 63 119 171 108 130 46 190 121 99 219 249 142 167 220 168 224 249 168 61 54)
   *Privr (248 148 179 185 130 100 196 122 238 78 101 10 230 150 76 244 2 227 25 212 241 42 21 240 122 207 198 61 28 22 35 123) 

   # initiator
   *Ei (ephemrl-pair)
   *Ci (hash32 *CONSTRUCTION)
   *Hi (hash32 (append *Ci *IDENTIFIER))
   *Hi (hash32 (append *Hi *Pubr))
   *Empty T
   *Ki NIL

   # responder
   *Er (ephemrl-pair)
   *Cr (hash32 *CONSTRUCTION)
   *Hr (hash32 (append *Cr *IDENTIFIER))
   *Hr (hash32 (append *Hr *Pubr))
   *Plain NIL
   *Kr NIL)
(de initiator NIL # write e, es, s, ss
   (make
      (link (pub *Ei))
      (setq 
         *Ci (kdf1 *Ci (pub *Ei))
         *Hi (hash32 (append *Hi (pub *Ei))) 
         @   (kdf2 *Ci (dh (prv *Ei) *Pubr))
         *Ci (car @)
         *Ki (cadr @) )
      (link (setq @ (lock_aead *Ki (nonce 0) *Pubi *Hi)))
      (setq *Hi (hash32 (append *Hi @))) ) )
(de initiator2 (Lst) # read e, ee, se
   (let (Er (car Lst)  Crypted (cadr Lst))
      (setq
         *Ci (kdf1 *Ci Er) 
         *Hi (hash32 (append *Hi Er))
         *Ci (kdf1 *Ci (dh (prv *Ei) Er))
         *Ci (kdf1 *Ci (dh *Privi Er))
         @   (kdf3 *Ci (need 32 0)) # zero PSK
         *Ci (car @)
         *Ki (caddr @)
         *Hi (hash32 (append *Hi (cadr @)))
         *Empty (unlock_aead *Ki (nonce 0) Crypted *Hi)
         *Hi (hash32 (append *Hi Crypted)) ) ) )
(de responder (Lst)
   (let (Ei (car Lst)  Crypted (cadr Lst))
      (make
         # read e, es, s, ss
         (setq
            *Cr (kdf1 *Cr Ei)
            *Hr (hash32 (append *Hr Ei))
            @   (kdf2 *Cr (dh *Privr Ei))
            *Cr (car @)
            *Kr (cadr @)
            *Plain (unlock_aead *Kr (nonce 0) Crypted *Hr)
            *Hr (hash32 (append *Hr Crypted)) )

         # between phases values are equal
         (test *Ci *Cr)
         (test *Ki *Kr)
         (test *Hi *Hr)
         (test *Pubi *Plain)

         # write e, ee, se
         (link (pub *Er))
         (setq
            *Cr (kdf1 *Cr (pub *Er))
            *Hr (hash32 (append *Hr (pub *Er)))
            *Cr (kdf1 *Cr (dh (prv *Er) Ei))
            *Cr (kdf1 *Cr (dh (prv *Er) *Plain)) 
            @   (kdf3 *Cr (need 32 0)) # zero PSK
            *Cr (car @)
            *Kr (caddr @) 
            *Hr (hash32 (append *Hr (cadr @))) )
         (link (setq @ (lock_aead *Kr (nonce 0) NIL *Hr)))
         (setq *Hr (hash32 (append *Hr @))) ) ) )

# full handshake steps
(initiator2
   (responder 
      (initiator) ) )

# after handshake values are equal too
(test NIL *Empty) # empty payload
(test *Hi *Hr)
(test *Ki *Kr)
(test *Ci *Cr)
# ready for split keys

(msg 'OK-phase1)
