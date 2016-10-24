{-# LANGUAGE DataKinds        #-}
{-# LANGUAGE DeriveGeneric    #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs            #-}
{-# LANGUAGE TypeFamilies     #-}
{-# LANGUAGE TypeOperators    #-}
{-# LANGUAGE OverloadedStrings#-}
module Api.User where

import Data.ByteString         as  BBS
import           Control.Monad.Logger
import qualified Control.Monad.Except as BE
import           Control.Monad.Reader        (ReaderT, runReaderT)
import           Control.Monad.Reader.Class
import           Data.Int                    (Int64)
-- import           Database.Esqueleto          as DE
import           Database.Persist.Postgresql (Entity (..), fromSqlKey, insert,
                                              selectFirst, selectList, (==.), runSqlConn, withPostgresqlPool, runSqlPool, ConnectionString)
import           Network.Wai
import           Servant
import           Servant.JS                  (vanillaJS, writeJSForAPI)

import           Config                      (App (..), Config (..), getConfig)
import           Control.Exception           (SomeException)
import           Control.Monad.Catch
import           Data.Aeson
import           Data.ByteString.Lazy.Char8  as  LBS
import           GHC.Generics
import           Models
import qualified Data.ByteString.Char8                as BS
import           Control.Monad.Trans.Control (MonadBaseControl)
import           Database.Persist.Sql
import           System.Log.FastLogger (fromLogStr)
import           Control.Monad
import           Data.Time
import           Control.Monad.IO.Class (liftIO)
import Data.Validation
import Control.Lens
import Servant.Server.Experimental.Auth (AuthHandler, AuthServerData,
                                         mkAuthHandler)
import Servant.Server.Experimental.Auth()
import Data.Text as T
import Data.Text.Encoding

import Web.JWT hiding (JSON)
import qualified Data.Map as Map

data Error = PasswordLengthShouldGT6
             | PasswordDoestMatchWithConfirmation
             deriving (Show)


data UserUpdate = UserUpdate { usid :: UserId
  , uname :: String
  , uemail :: String
} deriving (Show, Generic)

instance FromJSON UserUpdate


data UserRequest = UserRequest {
    rname :: String
  , email :: String
  , password :: String
  , confirmationPassword :: String
} deriving (Show, Generic)

instance FromJSON UserRequest

validatePasswordLength :: String -> AccValidation [Error] String
validatePasswordLength p =
  let l = Prelude.length p
  in
    if l >= 6
      then _Success # p
      else _Failure # [PasswordLengthShouldGT6]

validatePassword :: String -> String -> AccValidation [Error] String
validatePassword p cp =
    if cp == p
      then _Success # p
      else _Failure # [PasswordDoestMatchWithConfirmation]

validateUser :: UserRequest -> AccValidation [Error] UserRequest
validateUser (UserRequest n e p cp)=
  UserRequest <$> pure n <*> pure e <*> (validatePassword p cp *> validatePasswordLength p *> pure p) <*> pure cp


lookUpUser :: String -> Servant.Handler User
lookUpUser key = do
  cfg <- liftIO getConfig
  enter (convertAppx cfg) appUser
  where
    appUser = userFromDb key


convertAppx :: Config -> App :~> BE.ExceptT ServantErr IO
convertAppx cfg = Nat (flip runReaderT cfg . runApp)


userFromDb :: String -> App User
userFromDb str = do
  maybeUser <- runDb (selectFirst [UserName Database.Persist.Postgresql.==. str] [])
  case maybeUser of
    Nothing ->
      throwError err404
    Just person ->
      return $ entityVal person



validateAuthToken :: JWT VerifiedJWT -> Servant.Handler User
validateAuthToken token = do
   lookUpUser . getKeyFromToken $ unregisteredClaims $ claims token

getTokenFromAuthHeader :: BS.ByteString -> Maybe (JWT VerifiedJWT)
getTokenFromAuthHeader token =
  let
    (k, tkn) = breakOnEnd " " $ decodeUtf8 token
    mUnverifiedJwt = Web.JWT.decode tkn
  in
    verify (secret "secret-key") =<< mUnverifiedJwt

getKeyFromToken :: Map.Map Text Value -> String
getKeyFromToken cs =
  case lookup (T.pack "name") (Map.toList cs) of
    Nothing -> ""
    Just a ->
      case fromJSON a of
        Error s -> ""
        Data.Aeson.Success st -> st



authHandler :: AuthHandler Request User
authHandler =
  let handler req = case Prelude.lookup "Authorization" (requestHeaders req) of
        Nothing -> throwError err401
        Just key ->
          case getTokenFromAuthHeader key of
            Nothing -> throwError err401
            Just a -> validateAuthToken a
  in mkAuthHandler handler

type instance AuthServerData (AuthProtect "jwt-auth") = User

type UserAPI =
         "allusers" :> AuthProtect "jwt-auth" :> Get '[JSON] [Entity User]
    :<|> "users" :> Get '[JSON] ()
    :<|> "users" :> "bulk_update" :> ReqBody '[JSON] [UserUpdate] :> Post '[JSON] ()
    :<|> "users" :> Capture "name" String :> Get '[JSON] (Entity User)
    :<|> "users" :> ReqBody '[JSON] UserRequest :> Post '[JSON] Int64
    :<|> "getToken" :> ReqBody '[JSON] UserAuth :> Post '[JSON] UserAuth

data UserAuth = UserAuth
  { authName :: Text
  , token :: Maybe Text
  }
  deriving (Show, Generic)

instance FromJSON UserAuth
instance ToJSON UserAuth




data UserResponse = UserResponse {
  name    :: String,
  profile :: ProfileResponse
} deriving(Show, Generic)

instance ToJSON UserResponse

data ProfileResponse = ProfileResponse {
  age :: Int
} deriving(Show, Generic)

instance ToJSON ProfileResponse

userServer :: ServerT UserAPI App
userServer = allUsers :<|> runWithTransation :<|> bulkUpdate :<|> singleUser :<|> createUser :<|> authUser



authUser :: UserAuth -> App UserAuth
authUser uauth =
  let
    aname = authName uauth
    cs = def
      { iss = stringOrURI "AtomicITS"
      , unregisteredClaims = Map.fromList [("name", String $ aname)]
      }
    key = secret "secret-key"
    token = encodeSigned HS256 key cs
  in
    return $ UserAuth {authName = aname, token = (Just token)}


-- | Returns all users in the database.
allUsers :: User -> App [Entity User]
allUsers user = do
  liftIO $ Prelude.putStr $ show user
  -- To Test join need to install Esqueleto
  -- dataToJoin <- runDb (select $
  --             DE.from $ \(b, p) -> do
  --             where_ (b ^.UserId DE.==.  p ^.ProfileUserId)
  --             return (b,p))
  -- return $ mergeData dataToJoin

  runDb $ selectList [] []

mergeData :: [(Entity User, Entity Profile)] -> [UserResponse]
mergeData =
  Prelude.map joinData

joinData :: (Entity User, Entity Profile) -> UserResponse
joinData (usr, pro) =
  UserResponse {
    name = userName user,
    profile = prof
  }
  where
    prof = ProfileResponse {
      age = profileAge profile
    }
    user = entityVal usr
    profile = entityVal pro

-- | Returns a user by name or throws a 404 error.
singleUser :: String -> App (Entity User)
singleUser str = do
    maybeUser <- runDb (selectFirst [UserName Database.Persist.Postgresql.==. str] [])
    case maybeUser of
         Nothing ->
            throwError err404
         Just person ->
            return person


-- createUser :: User -> App Int64
-- createUser p = do
--     newUser <- runDb (insert (User (userName p) (userEmail p)))
--     return $ fromSqlKey newUser

-- createUser :: User -> App Int64

-- | Creates a user in the database.
createUser :: UserRequest -> App Int64
createUser p =
  case validateUser p of
    AccFailure e -> throwError $ err500 {errBody = LBS.pack (show e)}
    AccSuccess usr -> do
      time <- liftIO getCurrentTime
      newUser <- runDb $ insert (User (rname p) (email p) time time "")
      return $ fromSqlKey newUser

-- createUser :: UserRequest -> App Int64
-- createUser p = (do
--     time <- liftIO getCurrentTime
--     newUser <- runDb $ insert (User (rname p) (email p) time time "")
--     return $ fromSqlKey newUser) `catch` (\(SomeException e) -> throwError $ err500 {errBody= pack (show e)})


bulkUpdate :: [UserUpdate] -> App ()
bulkUpdate users =
  BE.liftIO $ flip runLoggingT (\_ _ _ s -> printDebug True s) $
    dbT $ caseTransactionUpdate users

caseTransactionUpdate :: [UserUpdate] -> ReaderT SqlBackend (LoggingT IO) ()
caseTransactionUpdate users = do
  mapM_ userUpdate users
  transactionSave
  return ()

userUpdate :: UserUpdate -> ReaderT SqlBackend (LoggingT IO) ()
userUpdate uu = do
  time <- liftIO getCurrentTime
  _ <- updateWhere [ UserId ==. usid uu ] [UserEmail =. uemail uu, UserName =. uname uu, UserUpdatedAt =. time]
  return ()

caseTransaction :: ReaderT SqlBackend (LoggingT IO) ()
caseTransaction = do
  time <- liftIO getCurrentTime
  _ <- insert (User "BNDName1" "email1@gmail.com" time time "")
  _ <- insert (User "BNDName2" "email2@gmail.com" time time "")
  _ <- insert (User "BNDName3" "email3@gmail.com" time time "")
  transactionUndo
  _ <- insert (User "ANDName4" "email4@gmail.com" time time "")
  _ <- insert (User "ANDName5" "email5@gmail.com" time time "")
  return ()

runWithTransation :: App ()
runWithTransation =
  BE.liftIO $ flip runLoggingT (\_ _ _ s -> printDebug True s) $
    dbT caseTransaction


-- dbT :: (MonadIO m, MonadBaseControl IO m) => SqlPersistT (LoggingT m) t -> m ()
dbT f =
  withPostgresqlPool connStr 1 $ runSqlPool f

connStr :: ConnectionString
connStr = BS.pack "host=localhost dbname=perservant user=postgres password=panda port=5432"



printDebug  debugPrint = if debugPrint then print . fromLogStr else void . return
