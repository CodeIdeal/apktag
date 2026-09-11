package core

import "errors"

var (
	ErrChannelExists   = errors.New("apktag: channel already exists")
	ErrChannelNotFound = errors.New("apktag: channel not found")
	ErrInvalidChannel  = errors.New("apktag: invalid channel")
	ErrInvalidMode     = errors.New("apktag: invalid mode")
	ErrReservedBlockID = errors.New("apktag: reserved APK Signing Block ID")
	ErrNoSigningBlock  = errors.New("apktag: APK Signing Block not found")
	ErrUnverifiedInput = errors.New("apktag: input signature is not verified")
)
