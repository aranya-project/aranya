module Jekyll
  module ListContent
    def echo_folder(folder)
      "Your folder: " + folder
    end

    def list_files(folder, type="*.png")
      files = Dir
        .glob(folder + "**/" + type)
        .select { |e| File.file? e }
        .join("<br>")
    end

    def list_folders(folder)
      folders = Dir
        .glob(folder + '**/*')
        .select { |e| File.directory? e }
        .join("<br>")
    end
  end
end

Liquid::Template.register_filter(Jekyll::ListContent)
