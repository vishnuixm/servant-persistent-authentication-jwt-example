{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE DataKinds, PolyKinds, TypeOperators#-}
{-# LANGUAGE MultiParamTypeClasses #-}
module AuthType where

import Data.Proxy
import Servant.Server
import Servant.Server.Internal
import Servant.API

data WithAuthentication


instance (HasServer sublayout config) => HasServer (WithAuthentication :> sublayout) config where
  type ServerT (WithAuthentication :> sublayout) m =
    WithAuthentication -> ServerT sublayout m

  route Proxy config subserver = undefined
