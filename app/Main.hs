module Main where

import           Database.Persist.Postgresql (runSqlPool)
import           Network.Wai.Handler.Warp    (run)
import           System.Environment          (lookupEnv)

import           Api                         (app)
import           Config                      (Config (..), Environment (..),
                                              makePool, setLogger, getConfig, lookupSetting)
import           Models                      (doMigrations)



-- | The 'main' function gathers the required environment information and
-- initializes the application.
main :: IO ()
main = do
  port <- lookupSetting "PORT" 8081
  cfg <- getConfig
  let logger = setLogger $ getEnv cfg
  runSqlPool doMigrations $ getPool cfg
  run port $ logger $ app cfg
