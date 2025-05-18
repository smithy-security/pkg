package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNilCheck(t *testing.T) {
	var nilStruct *struct{}
	assert.True(t, IsNil(nilStruct))

	var notNilStruct *struct{} = &struct{}{}
	assert.False(t, IsNil(notNilStruct))

	var someInterface interface{} = nilStruct
	assert.True(t, IsNil(someInterface))

	var someNotNilInterface interface{} = notNilStruct
	assert.False(t, IsNil(someNotNilInterface))

	var someFunc func()
	assert.True(t, IsNil(someFunc))

	var someNotNilFunc func() = func() {}
	assert.False(t, IsNil(someNotNilFunc))
}
