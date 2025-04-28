# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import string


class DOTGenerator:
    def __init__(self, package_data):
        self.dot = []
        self.package_data = package_data

    def getDOT(self):
        return self.dot

    def show(self, text):
        self.dot.append(text)

    def get_package(self, package_id):
        # Extract package name from package identifier.
        prefix = "SPDXRef-Package-"
        if prefix in package_id:
            # Format is SPDXRef-Package-n-<package>
            # Find package name after package number n
            startpos = len(prefix) + 1
            return package_id[package_id[startpos:].find("-") + startpos + 1 :]
        elif "-" in package_id and package_id[0] in string.digits:
            # Format is n-<package>
            return package_id[package_id.find("-") + 1 :]
        return package_id

    def get_license(self, package_id):
        for package in self.package_data:
            the_package = self.package_data[package]
            if the_package.get("name") == package_id:
                return the_package.get("licenseconcluded", "")
        return ""

    def set_colour(self, colour):
        base = " [shape=box, style=filled, fontcolor=white, fillcolor="
        return base + colour

    def set_label(self, label):
        license_label = self.get_license(self.get_package(label))
        if len(license_label) > 0:
            return f'label="{self.get_package(label)}\n{license_label}"'
        else:
            return f'label="{self.get_package(label)}"'

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
        root_found = False
        for element in data:
            source = element["source"]
            dest = element["target"]
            relationship = element["type"]

            lib = '"' + self.get_package(source) + '"'
            application = '"' + self.get_package(dest) + '"'
            lib_label = self.set_label(source)
            application_label = self.set_label(dest)

            # if not root_found and "DESCRIBES" in relationship:
            # if "DESCRIBES" in relationship:
            #     # Should probably only be one DESCRIBES relationship.
            #     root = application
                #root_found = True
            #else:
            if not root_found:
                root = application
                root_found = True
            if lib == root:
                if lib not in packages:
                    packages.append(lib)
                    self.show(f"\t{lib}{root_style} {lib_label}];")
                    root_found = True
                elif application not in packages:
                    packages.append(application)
                    # if root_found:
                    self.show(
                        f"\t{application}{explicit_style} {application_label}];"
                    )
            elif application == root:
                if lib not in packages:
                    packages.append(lib)
                    #if root_found:
                    self.show(f"\t{lib}{explicit_style} {lib_label}];")
            if lib not in packages:
                packages.append(lib)
                self.show(f"\t{lib}{implicit_style} {lib_label}];")
            if application not in packages:
                packages.append(application)
                self.show(
                    f"\t{application}{implicit_style} {application_label}];"
                )
            if lib != application and root_found:
                self.show("\t" + lib + " -> " + application + ";")
        self.show("}")
        # end
