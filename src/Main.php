<?php

namespace GeniusSystems\Paale;

use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;

use Illuminate\Http\Request;

class Main
{

  protected $request;

  function __construct(Request $request)
  {
    $this->request = $request;
  }

  public function isTokenValid(Signer $signer, Key $key)
  {
    $access_token = str_replace('Bearer ', '', $this->request->header("Authorization"));

    $token = (new Parser())->parse($access_token);

    return $token->verify($signer, $key);
  }

  public function isTokenExpired()
  {
    $access_token = str_replace('Bearer ', '', $this->request->header("Authorization"));
    $token = (new Parser())->parse($access_token);

    return $token->isExpired();
  }

  public function ownerMatches()
  {
    $access_token = str_replace('Bearer ', '', $this->request->header("Authorization"));
    $token = (new Parser())->parse($access_token);

    $sub = $token->getClaim('sub');

    return starts_with($this->request->getRequestUri(), $sub);
  }

  public function verify(Signer $signer, Key $key)
  {
    return
      $this->isTokenValid($signer, $key)
        && !$this->isTokenExpired()
        && $this->ownerMatches();
  }
}