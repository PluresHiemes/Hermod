#!/usr/bin/env python

"""
This class stores the information of users in a compact way
mod = modular base used in diffie hellman
base = the base that will be used for the exponent in diffie helman
pub = the public key of the user that this object will represent
shared = the shared secret between this user and the user running the 
            program
"""
class User():
    
    def __init__(self, name, modVal, baseVal, pubKey, sharedVal):
        self.userName = name
        self.mod = modVal
        self.base = baseVal
        self.pub = pubKey
        self.shared = sharedVal

    def getName():
        return self.userName
    
    def getMod():
        return self.mod
    
    def getBase():
        return self.base

    def getPub():
        return self.pub

    def getShared():
        return self.shared

    def setName(newName):
        self.userName = newName
        return self.userName
    
    def setMod(newMod):
        self.mod = newMod
        return self.mod
    
    def setBase(newBase):
        self.base = newBase
        return self.base

    def setPub(newPub):
        self.pub = newPub
        return self.pub

    def setShared(newShare):
        self.shared = newShare
        return self.shared

