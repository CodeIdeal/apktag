package core

import "errors"

var (
	ErrChannelExists   = errors.New("vasdolly: channel already exists")
	ErrChannelNotFound = errors.New("vasdolly: channel not found")
	ErrInvalidChannel  = errors.New("vasdolly: invalid channel")
	ErrInvalidMode     = errors.New("vasdolly: invalid mode")
	ErrReservedBlockID = errors.New("vasdolly: reserved APK Signing Block ID")
	ErrNoSigningBlock  = errors.New("vasdolly: APK Signing Block not found")
	ErrUnverifiedInput = errors.New("vasdolly: input signature is not verified")
)
