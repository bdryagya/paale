<?php

use PHPUnit\Framework\TestCase;
use Illuminate\Http\Request;
use GeniusSystems\Paale\Main as Paale;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key;

class PaaleTest extends TestCase {

  public function testCanBeInstantiated()
  {
    $request = Illuminate\Http\Request::create(
      "/users/10/posts", "GET", [], [], [], [], null
    );

    $paale = new Paale($request);

    $this->assertInstanceOf(Paale::class, $paale);
  }

  public function testValidatesAccessToken() {
    
    $request = Request::create(
      "/users/10/posts/5", "GET", [], [], [], [],null
    );

    $paale = new Paale($request);

    $this->expectException(InvalidArgumentException::class);

    $this->assertFalse($paale->verify(new Sha256(), new Key('testing123')));

    $token = (new Builder())
                ->issuedBy('https://auth.geniustv')
                ->permittedFor('https://resources.geniustv')
                ->expiresAt(time() + 3600)
                ->getToken(new Sha256(), new Key('testing123'));

    $request = Request::create(
      "/users/10/posts/5", "GET", [], [], [], [
        'HTTP_AUTHORIZATION'  => "Bearer " . $token,
      ],
      null
    );

    $paale = new Paale($request);

    $this->assertTrue($paale->isTokenValid(new Sha256(), new Key('testing123')));

    $this->assertFalse($paale->isTokenValid(new Sha256(), new Key('testing12')));
  }

  public function testVerifiesExpiryOfAccessToken() {
    $token = (new Builder())
                ->issuedBy('https://auth.geniustv')
                ->permittedFor('https://resources.geniustv')
                ->expiresAt(time() - 3600)
                ->getToken(new Sha256(), new Key('testing123'));

    $request = Request::create(
      "/users/10/posts/5", "GET", [], [], [], [
        'HTTP_AUTHORIZATION'  => "Bearer " . $token,
      ],
      null
    );

    $paale = new Paale($request);

    $this->assertTrue($paale->isTokenExpired());

    $token = (new Builder())
                ->issuedBy('https://auth.geniustv')
                ->permittedFor('https://resources.geniustv')
                ->expiresAt(time() + 3600)
                ->setSubject("/users/10")
                ->getToken(new Sha256(), new Key('testing123'));

    $request = Request::create(
      "/users/10/posts/5", "GET", [], [], [], [
        'HTTP_AUTHORIZATION'  => "Bearer " . $token,
      ],
      null
    );

    $paale = new Paale($request);

    $this->assertFalse($paale->isTokenExpired());
  }

  public function testVerifiesAuthorization()
  {
    $token = (new Builder())
                ->issuedBy('https://auth.geniustv')
                ->permittedFor('https://resources.geniustv')
                ->expiresAt(time() + 3600)
                ->setSubject("/users/10")
                ->getToken(new Sha256(), new Key('testing123'));

    $request = Request::create(
      "/users/10/posts/5", "GET", [], [], [], [
        'HTTP_AUTHORIZATION'  => "Bearer " . $token,
      ],
      null
    );
    
    $paale = new Paale($request);

    $this->assertTrue($paale->ownerMatches());

    $request = Request::create(
      "/users/5/posts/5", "GET", [], [], [], [
        'HTTP_AUTHORIZATION'  => "Bearer " . $token,
      ],
      null
    );
    
    $paale = new Paale($request);

    $this->assertFalse($paale->ownerMatches());
  }

  public function testVerifiesRequest()
  {
    $token = (new Builder())
                ->issuedBy('https://auth.geniustv')
                ->permittedFor('https://resources.geniustv')
                ->expiresAt(time() + 3600)
                ->setSubject("/users/10")
                ->getToken(new Sha256(), new Key('testing123'));

    $request = Request::create(
      "/users/10/posts/5", "GET", [], [], [], [
        'HTTP_AUTHORIZATION'  => "Bearer " . $token,
      ],
      null
    );
    
    $paale = new Paale($request);

    $this->assertTrue($paale->verify(new Sha256(), new Key('testing123')));

    $this->assertFalse($paale->verify(new Sha256(), new Key(123)));
  }
}