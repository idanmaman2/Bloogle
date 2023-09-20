#lang racket/base
(require net/url)
(require net/url-string)
(require net/url-structs)
(require net/http-client)
(define crawl-pool (string->url "https://m4gnum.xyz")  )
(display (request 'HEAD crawl-pool)) 
