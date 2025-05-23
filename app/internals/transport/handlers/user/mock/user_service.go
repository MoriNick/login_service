// Code generated by MockGen. DO NOT EDIT.
// Source: ./interfaces.go
//
// Generated by this command:
//
//	mockgen -source ./interfaces.go -destination ./mock/user_service.go
//

// Package mock_user is a generated GoMock package.
package mock_user

import (
	models "login/internals/models"
	reflect "reflect"

	gomock "go.uber.org/mock/gomock"
)

// MockUserService is a mock of UserService interface.
type MockUserService struct {
	ctrl     *gomock.Controller
	recorder *MockUserServiceMockRecorder
	isgomock struct{}
}

// MockUserServiceMockRecorder is the mock recorder for MockUserService.
type MockUserServiceMockRecorder struct {
	mock *MockUserService
}

// NewMockUserService creates a new mock instance.
func NewMockUserService(ctrl *gomock.Controller) *MockUserService {
	mock := &MockUserService{ctrl: ctrl}
	mock.recorder = &MockUserServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockUserService) EXPECT() *MockUserServiceMockRecorder {
	return m.recorder
}

// DeleteUserService mocks base method.
func (m *MockUserService) DeleteUserService(id string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteUserService", id)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteUserService indicates an expected call of DeleteUserService.
func (mr *MockUserServiceMockRecorder) DeleteUserService(id any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteUserService", reflect.TypeOf((*MockUserService)(nil).DeleteUserService), id)
}

// GetAllUsers mocks base method.
func (m *MockUserService) GetAllUsers(limit, offset uint64) ([]models.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAllUsers", limit, offset)
	ret0, _ := ret[0].([]models.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAllUsers indicates an expected call of GetAllUsers.
func (mr *MockUserServiceMockRecorder) GetAllUsers(limit, offset any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAllUsers", reflect.TypeOf((*MockUserService)(nil).GetAllUsers), limit, offset)
}

// GetUser mocks base method.
func (m *MockUserService) GetUser(id string) (*models.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUser", id)
	ret0, _ := ret[0].(*models.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUser indicates an expected call of GetUser.
func (mr *MockUserServiceMockRecorder) GetUser(id any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUser", reflect.TypeOf((*MockUserService)(nil).GetUser), id)
}

// Login mocks base method.
func (m *MockUserService) Login(param, password string) (string, string, string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Login", param, password)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(string)
	ret2, _ := ret[2].(string)
	ret3, _ := ret[3].(error)
	return ret0, ret1, ret2, ret3
}

// Login indicates an expected call of Login.
func (mr *MockUserServiceMockRecorder) Login(param, password any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Login", reflect.TypeOf((*MockUserService)(nil).Login), param, password)
}

// RefreshPassword mocks base method.
func (m *MockUserService) RefreshPassword(email, newPassword string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RefreshPassword", email, newPassword)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RefreshPassword indicates an expected call of RefreshPassword.
func (mr *MockUserServiceMockRecorder) RefreshPassword(email, newPassword any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RefreshPassword", reflect.TypeOf((*MockUserService)(nil).RefreshPassword), email, newPassword)
}

// Registration mocks base method.
func (m *MockUserService) Registration(email, nickname, password string) (string, string, string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Registration", email, nickname, password)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(string)
	ret2, _ := ret[2].(string)
	ret3, _ := ret[3].(error)
	return ret0, ret1, ret2, ret3
}

// Registration indicates an expected call of Registration.
func (mr *MockUserServiceMockRecorder) Registration(email, nickname, password any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Registration", reflect.TypeOf((*MockUserService)(nil).Registration), email, nickname, password)
}

// UpdateEmail mocks base method.
func (m *MockUserService) UpdateEmail(id, newEmail string) (*models.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateEmail", id, newEmail)
	ret0, _ := ret[0].(*models.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateEmail indicates an expected call of UpdateEmail.
func (mr *MockUserServiceMockRecorder) UpdateEmail(id, newEmail any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateEmail", reflect.TypeOf((*MockUserService)(nil).UpdateEmail), id, newEmail)
}

// UpdateNickname mocks base method.
func (m *MockUserService) UpdateNickname(id, newNickname string) (*models.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateNickname", id, newNickname)
	ret0, _ := ret[0].(*models.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateNickname indicates an expected call of UpdateNickname.
func (mr *MockUserServiceMockRecorder) UpdateNickname(id, newNickname any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateNickname", reflect.TypeOf((*MockUserService)(nil).UpdateNickname), id, newNickname)
}

// UpdatePassword mocks base method.
func (m *MockUserService) UpdatePassword(id, oldPassword, newPassword string) (*models.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdatePassword", id, oldPassword, newPassword)
	ret0, _ := ret[0].(*models.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdatePassword indicates an expected call of UpdatePassword.
func (mr *MockUserServiceMockRecorder) UpdatePassword(id, oldPassword, newPassword any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdatePassword", reflect.TypeOf((*MockUserService)(nil).UpdatePassword), id, oldPassword, newPassword)
}
