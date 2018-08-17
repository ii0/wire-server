{-# LANGUAGE ConstraintKinds     #-}
{-# LANGUAGE DeriveGeneric       #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE FlexibleInstances   #-}
{-# LANGUAGE GADTs               #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE QuasiQuotes         #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell     #-}
{-# LANGUAGE TupleSections       #-}
{-# LANGUAGE TypeApplications    #-}
{-# LANGUAGE ViewPatterns        #-}

{-# OPTIONS_GHC -Wno-orphans #-}

module Util.MockIdP where

import Control.Exception
import Control.Monad.Catch
import Control.Monad.Except
import Control.Monad.Reader
import Data.String
import Data.String.Conversions
import Data.UUID as UUID
import Data.UUID.V4 as UUID
import Data.Time (getCurrentTime)
import GHC.Stack
import Lens.Micro
import Network.HTTP.Types as HTTP
import Network.Wai
import SAML2.WebSSO
import Spar.Types
import Text.Hamlet.XML (xml)
import Text.XML
import Text.XML.DSig
import Text.XML.Util
import URI.ByteString
import Util.Credentials
import Util.Options
import Util.Types

import qualified Crypto.Random as Crypto
import qualified Control.Concurrent.Async          as Async
import qualified Data.ByteString.Lazy              as LBS
import qualified Network.Wai.Handler.Warp          as Warp
import qualified Network.Wai.Handler.Warp.Internal as Warp


-- serving an application

withMockIdP
    :: forall a m. (MonadIO m, MonadMask m, MonadReader TestEnv m)
    => Application -> m a -> m a
withMockIdP app go = do
  defs <- asks (endpointToSettings . (^. teMockIdp))
  srv <- liftIO . Async.async . Warp.runSettings defs $ app
  go `Control.Monad.Catch.finally` liftIO (Async.cancel srv)


-- test applications

serveMetaAndResp :: HasCallStack => FilePath -> HTTP.Status -> Application
serveMetaAndResp metafile respstatus req cont = case pathInfo req of
  ["meta"] -> cont . responseLBS status200 [] =<< LBS.readFile ("test-integration/resources/" <> metafile)
  ["resp"] -> cont $ responseLBS respstatus [] ""
  bad      -> error $ show bad


-- pure functions in lieu of a mock idp (faster & easier for testing)

newtype SignedAuthnResponse = SignedAuthnResponse Document
  deriving (Eq, Show)

mkAuthnResponse :: HasCallStack => IdP -> AuthnRequest -> Bool -> IO SignedAuthnResponse
mkAuthnResponse idp authnreq grantAccess = do
  assertionUuid <- UUID.toText <$> UUID.nextRandom
  respUuid      <- UUID.toText <$> UUID.nextRandom
  now           <- Time <$> getCurrentTime

  let issueInstant    = renderTime now
      expires         = renderTime $ 3600 `addTime` now
      issuer    :: ST = idp ^. idpIssuer . fromIssuer . to renderURI
      recipient :: ST = authnreq ^. rqIssuer . fromIssuer . to renderURI
      destination     = recipient
      inResponseTo    = renderID $ authnreq ^. rqID
      status
        | grantAccess = "urn:oasis:names:tc:SAML:2.0:status:Success"
        | otherwise   = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"

  assertion :: [Node]
    <- signElement
      [xml|
        <Assertion
          xmlns="urn:oasis:names:tc:SAML:2.0:assertion"
          Version="2.0"
          ID="#{assertionUuid}"
          IssueInstant="#{issueInstant}">
            <Issuer>
                #{issuer}
                <Subject>
                    <NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">
                        E3hQDDZoObpyTDplO8Ax8uC8ObcQmREdfps3TMpaI84
                    <SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                        <SubjectConfirmationData
                          InResponseTo="#{inResponseTo}"
                          NotOnOrAfter="#{expires}"
                          Recipient="#{recipient}">
                <Conditions NotBefore="#{issueInstant}" NotOnOrAfter="#{expires}">
                    <AudienceRestriction>
                        <Audience>
                            #{recipient}
                <AuthnStatement AuthnInstant="#{issueInstant}" SessionIndex="_e9ae1025-bc03-4b5a-943c-c9fcb8730b21">
                    <AuthnContext>
                        <AuthnContextClassRef>
                            urn:oasis:names:tc:SAML:2.0:ac:classes:Password
      |]

  let authnResponse :: Element
      [NodeElement authnResponse] =
        [xml|
          <samlp:Response
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            ID="#{respUuid}"
            Version="2.0"
            Destination="#{destination}"
            InResponseTo="#{inResponseTo}"
            IssueInstant="#{issueInstant}">
              <Issuer>
                  #{issuer}
              <samlp:Status>
                  <samlp:StatusCode Value="#{status}">
            ^{assertion}
        |]

  pure . SignedAuthnResponse $ mkDocument authnResponse


signElement :: HasCallStack => [Node] -> IO [Node]
signElement [NodeElement el] = do
  let docToNodes :: Document -> [Node]
      docToNodes (Document _ el' _) = [NodeElement el']
  eNodes :: Either String [Node]
    <- runExceptT . fmap docToNodes . signRoot sampleIdPPrivkey . mkDocument $ el
  either error pure eNodes
signElement bad = error $ show bad

-- use this only for the integration tests in this service.
instance Crypto.MonadRandom (ExceptT String IO) where
  getRandomBytes l = ExceptT $ Right <$> Crypto.getRandomBytes l


-- auxiliaries

endpointToSettings :: Endpoint -> Warp.Settings
endpointToSettings endpoint = Warp.defaultSettings { Warp.settingsHost = host, Warp.settingsPort = port }
  where
    host :: Warp.HostPreference = Data.String.fromString . cs $ endpoint ^. epHost
    port :: Int = fromIntegral $ endpoint ^. epPort

endpointToURL :: MonadIO m => Endpoint -> ST -> m URI
endpointToURL endpoint path = either err pure $ parseURI' urlst
  where
    urlst = "http://" <> host <> ":" <> port <> "/" <> path
    host  = cs $ endpoint ^. epHost
    port  = cs . show $ endpoint ^. epPort
    err   = liftIO . throwIO . ErrorCall . show . (, (endpoint, urlst))
