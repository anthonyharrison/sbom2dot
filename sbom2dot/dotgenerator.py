# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0


class DOTGenerator:
    def __init__(self):
        self.dot = []

    def getDOT(self):
        return self.dot

    def show(self, text):
        # print (text)
        self.dot.append(text)

    def get_package(self, package_id):
        # Extract package name from package identifier.
        prefix = "SPDXRef-Package-"
        if prefix in package_id:
            # Format is SPDXRef-Package-n-<package>
            # Find package name after package number n
            startpos = len(prefix) + 1
            return package_id[package_id[startpos:].find("-") + startpos + 1:]
        elif "-" in package_id:
            # Format is n-<package>
            return package_id[package_id.find("-") + 1:]
        return package_id

    def set_colour(self, colour):
        base = " [shape=box, style=filled, fontcolor=white, fillcolor="
        return base + colour + "];"

    def generatedot(self, data):

        if len(data) == 0:
            return
        # Generate header
        self.show("strict digraph sbom {")
        self.show('\tsize="8,10.5"; ratio=fill;')
        # Generate graph
        root = ""
        explicit_style = self.set_colour("royalblue")
        implicit_style = self.set_colour("darkgreen")
        root_style = self.set_colour("darkred")
        packages = []
        for element in data:
            source = element["source"]
            dest = element["target"]
            relationship = element["type"]

            lib = '"' + self.get_package(source) + '"'
            application = '"' + self.get_package(dest) + '"'

            if relationship == " DESCRIBES ":
                # Should only be one DESCRIBES relationship.
                root = application
            else:
                if lib == root:
                    if lib not in packages:
                        packages.append(lib)
                        self.show("\t" + lib + root_style)
                    if application not in packages:
                        packages.append(application)
                        self.show("\t" + application + explicit_style)
                elif application == root:
                    if lib not in packages:
                        packages.append(lib)
                        self.show("\t" + lib + explicit_style)
                else:
                    if lib not in packages:
                        packages.append(lib)
                        self.show("\t" + lib + implicit_style)
                    if application not in packages:
                        packages.append(application)
                        self.show("\t" + application + implicit_style)
                if lib != application:
                    self.show("\t" + lib + " -> " + application + ";")
        self.show("}")
        # end
