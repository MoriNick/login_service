package user

// ------------------
// |Request entities|
// ------------------

type registrationEntity struct {
  Email string    `json:"email"`
  Nickname string `json:"nickname"`
  Password string `json:"password"`
}

type loginEntity struct {
  Param string    `json:"param"`
  Password string `json:"password"`
}

type refreshPassword struct {
  Email string        `json:"email"`
  NewPassword string  `json:"new_password"`
}

type updatePassword struct {
  OldPassword string `json:"old_password"`
  NewPassword string `json:"new_password"`
}

type updateEmail struct {
  NewEmail string `json:"new_email"`
}

type updateNickname struct {
  NewNickname string `json:"new_nickname"`
}

// -------------------
// |Response entities|
// -------------------

type responseUserId struct {
  Id string `json:"id"`
}

type responseError struct {
  Error string `json:"error"`
}

type responseUser struct {
  Id string       `json:"id"`
  Email string    `json:"email"`
  Nickname string `json:"nickname"`
}
